from core.models import Identity
from core.models import Provider
from core.query import contains_credential
from service.driver import get_esh_driver
from atmosphere import settings
from service.tasks.driver import sync_atm_with_openstack

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
        logger.info("TokenUpdateSerializer:validate called")
        # create will fail if it is an invalid token, but we need to create an identity first
        # inorder to put the appropriate credentials on it.
        return data

    def create(self, data):
        logger.info("TokenUpdateSerializer::create called")
        identity = self._find_identity_match(data['provider'], data['username'])
        if not identity:
            identity = self._create_identity(data['provider'],
                                             data['username'],
                                             data.get('project_name'),
                                             data.get('token'))
        logger.info("  Openstack Token being (%s) %s" % (data['username'], data['token']))
        identity.update_credential(identity, 'key', data['username'], replace=True)
        identity.update_credential(identity, 'ex_force_auth_token', data['token'], replace=True)
        identity.update_credential(identity,
                                   'ex_force_auth_url',
                                   settings.AUTHENTICATION['KEYSTONE_SERVER'],
                                   replace=True)
        # Note: sync_atm_with_openstack will add the following credentials
        #       ex_force_base_url
        #       ex_tenant_name
        #       ex_project_name
        #       cat_<os project id> - json catalog for each project
        sync_atm_with_openstack.delay(identity.id)
        logger.info("TokenUpdateSerializer::create finished")
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

    def _create_identity(self, provider_uuid, username, project_name, token):
        try:
            provider = Provider.objects.get(uuid=provider_uuid)
        except Provider.DoesNotExist:
            raise serializers.ValidationError("Provider %s is invalid" % provider)
        identity = Identity.create_identity(username, provider.location)
        return identity

    def _find_identity_match(self, provider_uuid, username):
        try:
            provider = Provider.objects.get(uuid=provider_uuid)
        except Provider.DoesNotExist:
            raise serializers.ValidationError("Provider %s is invalid" % provider)

        request_user = self._get_request_user()
        ident = Identity.objects\
            .filter(created_by=request_user, provider=provider)\
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
