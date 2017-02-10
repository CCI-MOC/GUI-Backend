from rest_framework.decorators import detail_route
from rest_framework.response import Response
from rest_framework import status
from rest_framework import filters
import django_filters

from django.contrib.auth.models import AnonymousUser

from core.models import Identity

from api.v2.serializers.post import TokenUpdateSerializer
from api.v2.views.base import AuthViewSet

from threepio import logger

class TokenUpdateViewSet(AuthViewSet):
    """
    API endpoint that allows providers to be viewed or edited.
    """
    lookup_fields = ("id", "uuid")
    queryset = Identity.objects.all()
    serializer_class = TokenUpdateSerializer
    #add get for now - get isn't called by the UI, but the UI announces that get cannot be used.
    http_method_names = ['get', 'post', 'head', 'options', 'trace']

    def create(self, request):
        logger.info("TokenUpdateViewSet::create");
        #note: this is called first before the serializer
        #token=request.data['token']
        #setting a value for the project_name to make the current serializer happy
        #not sure how to make it no be required
        request.data[u'project_name']='a';
        logger.info(repr(request.data))
        return super(AuthViewSet, self).create(request) 

    def get_queryset(self):
        """
        Filter providers by current user
        """
        user = self.request.user
        if (type(user) == AnonymousUser):
            return Identity.objects.none()
        logger.info("TokenUpdateViewSet:get_queryset user: %" % (user.username)) 
        identities = user.current_identities()
        return identities
