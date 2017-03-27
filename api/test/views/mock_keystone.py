import json

from rest_framework import status
from rest_framework.response import Response
from django.http import Http404
from rest_framework.views import APIView
from rest_framework import status
from django.http import JsonResponse, HttpResponse

from threepio import logger

from atmosphere import settings
from atmosphere.settings.local import AUTHENTICATION as auth_settings
from atmosphere.settings.local import TEST as test_settings


class MockKeystoneView(APIView):
    """
    This is just a simple view to simulate keystone authentication
    """

    def get(self, request):
        logger.info(" get called: ")
        #logger.info(request.query_params.list())
        return JsonResponse({'text':'get response'}) 

    def post(self, request):
        logger.info("post called: ")
        logger.info(request.body)
        ks_request=json.loads(request.body)
        logger.info(repr(ks_request['auth']['identity']['password']['user']['name']))
        logger.info(repr(ks_request['auth']['identity']['password']['user']['password']))
        if (ks_request['auth']['identity']['password']['user']['name'] == test_settings['username']
                and ks_request['auth']['identity']['password']['user']['password'] == test_settings['password']):
            json_text = '{"token": {"issued_at": "2017-03-27T14:33:34.000000Z", "audit_ids": ["xM40d8iLTGS-CaE70Xki7A"], "methods": ["password"], "expires_at": "2017-03-27T15:33:34.000000Z", "user": {"domain": {"id": "default", "name": "Default"}, "id": "6705630a653f4300baf486a8df6072de", "name": ' + test_settings['username'] + '}}}'
            logger.info("*** success ***")
            response=HttpResponse(json_text,status=status.HTTP_201_CREATED,content_type='application/javascript')
            response['x-openstack-request_id']='req-4227f7a0-4631-4014-8c70-d0bf42ff6553'
            response['Vary']='X-Auth-Token'
            return response
        else:
            json_text = '{"error": {"message": "The request you have made requires authentication.", "code": 401, "title": "Unauthorized"}}'
            logger.info("*** failed ***")
            return HttpResponse(json_text,status=status.HTTP_401_UNAUTHORIZED,content_type='application/javascript')
