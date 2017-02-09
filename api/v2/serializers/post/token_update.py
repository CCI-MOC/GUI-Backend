from core.models import ( AtmosphereUser, Identity, Provider)
from core.query import contains_credential
from service.driver import get_esh_driver
from api.v2.serializers.summaries import IdentitySummarySerializer
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client

import requests
import json

from rest_framework import serializers

from threepio import logger

class TokenUpdateSerializer(serializers.ModelSerializer):
    """
    """
    # Flags
    username = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)
    project_name = serializers.CharField(write_only=True)
    provider = serializers.UUIDField(format='hex_verbose', write_only=True)
    identity_uuid = serializers.CharField(source='uuid', read_only=True)

    def validate(self, data):
        """
        IF identity is found validation will:
        - Ensure that user/token produces a valid driver
        """
        logger.info("TokenUpdateSerializer:validate called")
        #create will fail if it is an invalid token, but we need to create an identity first
        #inorder to put the appropriate credentials on it.
        return data

    def create(self, data):
        logger.info("TokenUpdateSerializer::create called");
        logger.info("find identity")
        identity = self._find_identity_match(data['provider'], data['username'], data['project_name'])
        if not identity:
            logger.info("create identity")
            identity = self._create_identity(data['provider'], data['username'], data['project_name'], data['token'])
            #return identity
        logger.info("cred -> ex_force_auth_token = %s" % (data['token']))
        identity.update_credential(identity, 'key', data['username'], replace=True)
        identity.update_credential(identity, 'ex_force_auth_token', data['token'], replace=True)
        identity.update_credential(identity, 'ex_force_auth_url', 'https://engage1.massopencloud.org:5000', replace=True) 

        logger.info("trying to find project_id")
        #this is mostly for future reference, though at this point all tokens being passed to here are scoped!
        auth_url=('https://engage1.massopencloud.org:5000'+'/v3')
        token_auth=v3.Token(auth_url=auth_url,
                            token=data['token'],
                            unscoped=True)
        
        response = requests.get('https://engage1.massopencloud.org:5000'+ '/v3' + '/auth/tokens?nocatalog',
                                headers={'x-auth-token': data['token'], 'x-subject-token': data['token']})
        try:
            project = json.loads(response.text)['token']['project']
        except KeyError:
            logger.info("cannot find Openstack project - using default project id") 
            #TODO: get default project name from token
            raise serializers.ValidationError("Invalid token passed")
            #if this doesn't work raise a bad token (and delete all of the creds associated with the identity.
        logger.info("cred -> ex_force_base_url")
        identity.update_credential(identity, 'ex_force_base_url', 'https://engage1.massopencloud.org:8774/v2/'+str(project['id']), replace=True) 
        identity.update_credential(identity, 'ex_tenant_name',str(project['name']));
        identity.update_credential(identity, 'ex_project_name',str(project['name']));
        logger.info("TokenUpdateSerializer::create finished")
        return identity

    def validate_token_with_driver(self, provider_uuid, username, project_name, new_token_key):
        ident = self._find_identity_match(provider_uuid, username, project_name)
        if not ident:
            # Can't validate driver if identity can't be created.
            return
        try:
            driver = get_esh_driver(ident, identity_kwargs={'ex_force_auth_token': new_token_key})
            if not driver.is_valid():
                raise serializers.ValidationError(
                    "Token returned from keystone could not create an rtwo driver")
        except Exception as exc:
                raise serializers.ValidationError(
                        "Driver could not be created: %s" % exc)

    def _create_identity(self, provider_uuid, username, project_name, token):
        try:
            provider = Provider.objects.get(uuid=provider_uuid)
        except Provider.DoesNotExist:
            raise serializers.ValidationError("Provider %s is invalid" % provider)
        identity = Identity.create_identity(username, provider.location)
        #RBB: The calling function creates the user credentials needed (there are more needed than username, project_name, token )
        #    cred_key=username, cred_ex_project_name=project_name, cred_ex_force_auth_token=token)
        # FIXME: In a different PR re-work quota to sync with the values in OpenStack. otherwise the value assigned (default) will differ from the users _actual_ quota in openstack.
        # Note: this is putting the cart before the horse!!
        #self.validate_token_with_driver(provider_uuid, username, project_name, token)
        return identity

    def _find_identity_match(self, provider_uuid, username, project_name):
        try:
            provider = Provider.objects.get(uuid=provider_uuid)
        except Provider.DoesNotExist:
            raise serializers.ValidationError("Provider %s is invalid" % provider)

        request_user = self._get_request_user()
        ident = Identity.objects\
            .filter(
                contains_credential('key', username),
                created_by=request_user, provider=provider)\
            .filter(
                contains_credential('ex_project_name', project_name) | contains_credential('ex_tenant_name', project_name))\
            .first()
        return ident

    def _get_request_user(self):
        if 'request' in self.context:
            return self.context['request'].user
        elif 'user' in self.context:
            return self.context['user']
        else:
            raise ValueError("Expected 'request/user' to be passed in via context for this serializer")

    class Meta:
        model = Identity
        fields = (
            'provider',
            'identity_uuid',
            'username',
            'project_name',
            'token'
        )
