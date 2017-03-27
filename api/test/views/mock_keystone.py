import json

from rest_framework import status
from rest_framework.response import Response
from django.http import Http404
from rest_framework.views import APIView
from rest_framework import status
from django.http import JsonResponse

from threepio import logger

class MockKeystoneView(APIView):
    """
    This is just a simple view to simulate keystone authentication
    """

    def get(self, request):
        logger.info(" get called: ")
        logger.info(request.query_params.list())
        return JsonResponse({'text':'get response'}) 

    def post(self, request):
        logger.info("post called: ")
        ks_request=json.loads(request.body)
        logger.info(repr(ks_request['auth']['identity']['password']['user']['name']))
        if ks_request['auth']['identity']['password']['user']['name'] == u'MOCKYMOCK'\
                and ks_request['auth']['identity']['password']['user']['name'] == u'MOCKYMOCK':
            logger.info("**** success *****")
        else:
            logger.info("**** fail ****")
        return JsonResponse({'text':'Post Response'})

