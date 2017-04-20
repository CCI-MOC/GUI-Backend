from django.contrib.auth import authenticate, login

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from atmosphere.settings import secrets
from django_cyverse_auth.models import create_token, lookupSessionToken

from api.permissions import ApiAuthIgnore
from api.exceptions import invalid_auth
from api.v1.serializers import TokenSerializer

from core.query import contains_credential

from core.models import AtmosphereUser as User
from core.models import Provider, Identity
from service.tasks.sync_project import sync_atm_with_openstack
from atmosphere import settings
from atmosphere.settings.local import AUTHENTICATION as auth_settings
from atmosphere.settings.local import TEST as test_settings

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client

from threepio import logger


class Authentication(APIView):

    permission_classes = (ApiAuthIgnore,)

    def get(self, request):
        user = request.user
        if not user.is_authenticated():
            return Response("Logged-in User or POST required "
                            "to retrieve AuthToken",
                            status=status.HTTP_403_FORBIDDEN)
        token = lookupSessionToken(request)
        if not token:
            token = create_token(user.username, request.session.pop('token_key', None))
        serialized_data = TokenSerializer(token).data
        return Response(serialized_data, status=status.HTTP_200_OK)

    def post(self, request):
        data = request.data
        username = data.get('username', None)
        password = data.get('password', None)
        project_name = data.get('project_name', None)
        auth_url = data.get('auth_url', None)
        if not username:
            return invalid_auth("Username missing")

        auth_kwargs = {"username": username, "password": password, "request": request}
        if project_name and auth_url:
            auth_kwargs['project_name'] = project_name
            auth_kwargs['auth_url'] = auth_url
        # This authenticate will fail if the username is not in the database
        # if the user doesn't exist - create the user
        created_user = False
        try:
            u = User.objects.get(username=username)  # see if the account exists
        except:
            u = User()
            u.username = username
            u.password = "TrustNoOne"  # we don't use this for keystone
            u.save()
            created_user = True

        user = authenticate(**auth_kwargs)
        if not user:
            if created_user:
                u.delete()
            return invalid_auth("Username/Password combination was invalid")

        login(request, user)

        if 'django_cyverse_auth.authBackends.OpenstackLoginBackend' in settings.AUTHENTICATION_BACKENDS:
            # This was added as the token serializer is not always being called.
            # Currently there should only be one identity
            prov = [Provider.objects.get(public=True)]
            if len(prov) > 0:
                identity_list = Identity.objects.filter(created_by=user, provider=prov[0])
                if len(identity_list) > 0:
                    identity = identity_list[0]
                else:
                    identity = Identity.create_identity(user.username, prov[0].location, cred_key=user.username)
                identity.update_credential(identity, 'key', user.username, replace=True)

                # need to get a keystone token
                logger.info("token: %s" % request.session.get('token_key', "--empty--"))
                token_key = request.session.get('token_key')
                if not token_key:
                    # The first time logging in yealds a null token
                    password_auth = v3.Password(
                        auth_url=settings.AUTHENTICATION['KEYSTONE_SERVER'],
                        user_domain_name=settings.AUTHENTICATION['KEYSTONE_DOMAIN_NAME'],
                        username=username, password=password,
                        unscoped=True)
                    ks_session = session.Session(auth=password_auth)
                    token_key = ks_session.get_token()

                identity.update_credential(identity, 'ex_force_auth_token', token_key, replace=True)
                auth_url = settings.AUTHENTICATION['KEYSTONE_SERVER']
                identity.update_credential(identity, 'ex_force_auth_url', settings.AUTHENTICATION['KEYSTONE_SERVER'], replace=True)
                sync_atm_with_openstack(identity.id)  # .delay(identity.id) RBB celery doesn't play nice with travis

        issuer_backend = request.session.get('_auth_user_backend', '').split('.')[-1]
        return self._create_token(
            request, user.username, request.session.pop('token_key', None),
            issuer=issuer_backend)

    def _create_token(self, request, username, token_key, issuer="DRF"):
        token = create_token(username, token_key, issuer=issuer)
        expireTime = token.issuedTime + secrets.TOKEN_EXPIRY_TIME
        auth_json = {
            'token': token.key,
            'username': token.user.username,
            'expires': expireTime.strftime("%b %d, %Y %H:%M:%S")
        }
        request.session['token'] = token.key
        return Response(auth_json, status=status.HTTP_201_CREATED)
