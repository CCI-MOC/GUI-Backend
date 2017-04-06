from core.models import (Identity, Provider)
from core.query import contains_credential
from service.driver import get_esh_driver
from api.v2.serializers.summaries import IdentitySummarySerializer
from atmosphere import settings
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
    project_name = serializers.CharField(required=False, allow_null=True)
    provider = serializers.UUIDField(format='hex_verbose', write_only=True)
    identity_uuid = serializers.CharField(source='uuid', read_only=True)

    def validate(self, data):
        """
        IF identity is found validation will:
        - Ensure that user/token produces a valid driver
        """
        return data

    def create(self, data):
        identity = self._find_identity_match(data['provider'], data['username'])
        if not identity:
            identity = self._create_identity(data['provider'], data['username'], data['token'])
        identity.update_credential(identity, 'key', data['username'], replace=True)
        identity.update_credential(identity, 'ex_force_auth_token', data.get('token'), replace=True)
        auth_url = settings.AUTHENTICATION['KEYSTONE_SERVER'] + '/v3'
        identity.update_credential(identity, 'ex_force_auth_url', settings.AUTHENTICATION['KEYSTONE_SERVER'], replace=True)
        response = requests.get(auth_url + '/auth/tokens', headers={'x-auth-token': data['token'], 'x-subject-token': data['token']})
        try:
            catalog = json.loads(response.text)
            project = catalog['token']['project']
        except KeyError:
            raise serializers.ValidationError("Invalid token passed")
        enpoint_catalog = catalog['token']['catalog']
        comput = None
        for listing in enpoint_catalog:
            if listing['type'] == 'compute':
                compute = listing
        if not compute:
            raise serializers.ValidationError("Cannot find compute endpoint catalog")
        compute_url = None
        for ep in compute['endpoints']:
            if ep['interface'] == 'public':
                compute_url = ep['url']
        if not compute_url:
            raise serializers.ValidationError("Cannot find a public compute endpoint url")
        identity.update_credential(identity, 'ex_force_base_url', compute_url, replace=True)
        identity.update_credential(identity, 'ex_tenant_name', str(project['name']))
        identity.update_credential(identity, 'ex_project_name', str(project['name']))
        return identity

    def validate_token_with_driver(self, provider_uuid, username, project_name, new_token_key):
        ident = self._find_identity_match(provider_uuid, username)
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

    def _create_identity(self, provider_uuid, username, token):
        try:
            provider = Provider.objects.get(uuid=provider_uuid)
        except Provider.DoesNotExist:
            raise serializers.ValidationError("Provider %s is invalid" % provider)
        identity = Identity.create_identity(
            username, provider.location,
            cred_key=username, cred_ex_force_auth_token=token)
        # FIXME: In a different PR re-work quota to sync with the values in OpenStack. otherwise the value assigned (default) will differ from the users _actual_ quota in openstack.
        return identity

    def _find_identity_match(self, provider_uuid, username):
        try:
            provider = Provider.objects.get(uuid=provider_uuid)
        except Provider.DoesNotExist:
            raise serializers.ValidationError("Provider %s is invalid" % provider)

        request_user = self._get_request_user()
        ident = Identity.objects\
            .filter(
                contains_credential('key', username),
                created_by=request_user, provider=provider)\
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
