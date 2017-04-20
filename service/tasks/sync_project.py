from django.conf import settings
from django.utils.timezone import datetime, timedelta
from celery.decorators import task
from celery.task import current
from celery.result import allow_join_result
from rest_framework import serializers

from core.models.instance import Instance
from core.models.identity import Identity
from core.models.profile import UserProfile
from core.models import Group
from core.models import Leadership
from core.models import Project

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client

from threepio import logger, celery_logger
import requests
import json


def get_unscoped_token_and_session(os_auth_url, os_token):
    token_auth = v3.Token(auth_url=os_auth_url,
                          token=os_token,
                          unscoped=True)
    unscoped_sess = session.Session(auth=token_auth)
    unscoped_token = unscoped_sess.get_token()
    return (unscoped_token, unscoped_sess)


def set_active_os_project(identity_id, os_project_id):
    try:
        identity = Identity.objects.get(id=identity_id)
        atm_project = Project.objects.get(os_project_id=os_project_id)
    except Exception as e:
        logger.info(e.message)
    creds = identity.get_all_credentials()
    identity.update_credential(identity,
                               "ex_force_base_url",
                               creds.get('compute_' + str(os_project_id)),
                               replace=True)
    identity.update_credential(identity,
                               "ex_tenant_name",
                               atm_project.name,
                               replace=True)
    identity.update_credential(identity,
                               "ex_project_name",
                               atm_project.name,
                               replace=True)


def get_or_create_user_group(atm_user):
    """
    This returns the group associated with a user and sets the relationships
    with that group.
    """
    try:
        group = Group.objects.get(name=atm_user.username)
    except:
        group = Group(name=atm_user.username)
        group.save()
    # ensure the user is added a leader and member of their group
    #    members can view providers (and perhaps instances)
    #    leaders can view images (but not providers)
    try:
        lead = Leadership.objects.get(user=atm_user, group=group)
    except:
        lead = Leadership(userid_id=atm_user.id, group_id=group.group_ptr_id)
        lead.save()
    # ensure that the user id is added as a member of that group
    group.user_set.add(atm_user)
    group.save()
    return group


def get_or_create_atm_project(os_project, group_id):
    """
    This gets or creates the atmosphere  project
    """
    celery_logger.info("os_project: ")
    celery_logger.info(repr(os_project))
    try:
        atm_project = Project.objects.get(os_project_id=os_project.id)
    except:
        # if we cannot get the project (group is a FK in the project)
        atm_project = Project()
        atm_project.owner_id = group_id
    atm_project.name = os_project.name
    atm_project.os_domain_id = os_project.domain_id
    atm_project.os_project_id = os_project.id
    atm_project.save()
    celery_logger.info("atm_project: ")
    celery_logger.info(repr(atm_project))
    return atm_project


def get_os_scoped_token(auth_url, unscoped_token, os_project_id):
    scoped_token_auth = v3.Token(auth_url=auth_url,
                                 token=unscoped_token,
                                 project_id=os_project_id,
                                 unscoped=False)
    scoped_sess = session.Session(auth=scoped_token_auth)
    scoped_token = scoped_sess.get_token()
    return scoped_token


def get_os_project_catalog(auth_url, scoped_token):
    """
    gets the openstack service catalog
    """
    response = requests.get(auth_url + '/auth/tokens',
                            headers={'x-auth-token': scoped_token,
                                     'x-subject-token': scoped_token})
    return response.text


def get_compute_url(json_catalog):
    celery_logger.info("start of get_compute_url")
    try:
        catalog = json.loads(json_catalog)
    except KeyError:
        celery_logger.info("Invalid token passed")
        raise serializers.ValidationError("Invalid token passed")
    endpoint_catalog = catalog['token']['catalog']
    compute = None
    for item in endpoint_catalog:
        if item['type'] == 'compute':
            compute = item
    if not compute:
        celery_logger.info("Cannot find compute endpoint catalog")
        raise serializers.ValidationError("Cannot find compute endpoint catalog")
    compute_url = None
    for ep in compute['endpoints']:
        if ep['interface'] == 'public':
            compute_url = ep['url']
    if not compute_url:
        celery_logger("Cannot find a public compute enpoint url")
        raise serializers.ValidationError("Cannot find a public compute endpoint url")
    celery_logger.info("end of get_compute_url")
    return compute_url


# TODO: RBB Uncomment the following line to make this a celery task.  This needs to be done
#       when performance is impacted.
# @task(name="sync_atm_with_openstack")
def sync_atm_with_openstack(identity_id):
    #  - There is nothing to return here.  It just syncs the database
    celery_logger.info("sync_atm_with_openstack:  identity_id=%s"
                       % (str(identity_id)))
    identity = Identity.objects.get(id=identity_id)
    atm_user = identity.created_by
    creds = identity.get_all_credentials()
    auth_url = creds['ex_force_auth_url']
    auth_token = creds['ex_force_auth_token']
    (unscoped_token, unscoped_sess) = get_unscoped_token_and_session(auth_url,
                                                                     auth_token)
    os_user_id = unscoped_sess.get_user_id()
    unscoped_keystone = client.Client(session=unscoped_sess)
    os_project_list = unscoped_keystone.projects.list(user=os_user_id)
    atm_group = get_or_create_user_group(atm_user)
    # keep track of all of the active projects so it is known which ones to
    # delete.
    active_atm_projects = []
    for os_project in os_project_list:
        celery_logger.info("Syncing OS Project: %s:%s %s" % (str(os_project.domain_id),
                           str(os_project.name), str(os_project.id)))
        atm_project = get_or_create_atm_project(os_project, atm_group.id)
        if atm_project:
            scoped_token = get_os_scoped_token(auth_url,
                                               unscoped_token,
                                               os_project.id)
            catalog_json = get_os_project_catalog(auth_url, scoped_token)
            compute_url = get_compute_url(catalog_json)
            # In the future, we will need to process the catalog to find the urls
            # to each of the services
            identity.update_credential(identity,
                                       'tok_' + str(os_project.id),
                                       scoped_token,
                                       replace=True)
            identity.update_credential(identity,
                                       'compute_' + str(os_project.id),
                                       compute_url,
                                       replace=True)
            active_atm_projects.append(atm_project.id)
            # Sync compute nodes  - Placeholder
            # sync_os_compute_nodes.delay(atm_user.id,
            #                            atm_project.id,
            #                            compute_url,
            #                            scoped_token)
        # get volumnes
    celery_logger.info("Remove atmosphere projects that are not in OpenStack")
    # clean up old projects
    all_atm_projects = Project.objects.all().filter(owner_id=atm_group.id)
    for atm_project in all_atm_projects:
        if atm_project.id not in active_atm_projects:
            atm_project.delete()
    set_active_os_project(identity_id, os_project_list[0].id)
    celery_logger.info("end of sync")
