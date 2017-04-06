import json
from rest_framework import status
from rest_framework.views import APIView
from django.http import HttpResponse

from threepio import logger

from atmosphere import settings
from atmosphere.settings.local import AUTHENTICATION as auth_settings
from atmosphere.settings.local import TEST as test_settings

# Some json strings

EXPECTED_UNSCOPED_TOKEN = "gAAAAABY2WAKlR6yxvn1mvkPcW0i4fB36y68N0mg2u1CUjPg7OJ-alV2CPPg207_zOTm8s3p3hHJWYVCw5Jh3PBYECkdplVgdzH7UgviSftNM8AJboFNXbypNNaELqgSztpGh5TnBbXI5RlzAc4IIBWd8wPL-RZuOA"
EXPECTED_SCOPED_TOKEN = "gAAAAABY2qmscjNU6DB-01NFpTAxSH35C07vC6SFc3enD4NiZfBYjzT_rFMDEM-Rt0GD0-n7T_K_ain-Z8_n6ESOBQk6-QfS8I8X_YLWYA2jHhHq_KsQEfoefU_XOmb46nJ_kl0lJWsQ4fplQSaudPLPs9eqgWn4E6qntp6sGoNppiv5kECZZfAoKa9STmjksBvksRBaB2Vp"
EXPECTED_USER_ID = "6705630a653f4300baf486a8df6072de"
JSON_401 = '{"error": {"message": "The request you have made requires authentication.", "code": 401, "title": "Unauthorized"}}'
JSON_403 = '{"error": {"message": "You are not authorized to perform the requested action: identity:list_user_projects", "code": 403, "title": "Forbidden"}}'
JSON_404 = '{"error": {"message": "Not Found.", "code": 404, "title": "Not Found"}}'
JSON_404A = '{"error": {"message": "This is not a recognized Fernet token ", "code": 404, "title": "Not Found"}}'

JSON_BASEURL = '''{"version": {"status": "stable", "updated": "2016-10-06T00:00:00Z", "media-types": [{"base": "application/json",
"type": "application/vnd.openstack.identity-v3+json"}], "id": "v3.7", "links": [{"href": "http://localhost:8082/api/test/keystone/v3/",
"rel": "self"}]}}
'''
JSON_USERSPROJECTS = '''{"links": {"self": "http://localhost:8082/api/test/keystone/v3/users/6705630a653f4300baf486a8df6072de/projects", "previous": null,
"next": null}, "projects": [{"is_domain": false, "description": "a test", "links": {"self": "http://localhost:8082/api/test/kestone/v3/projects/190ce9f5a454493e9eaae608d54fe2d1"},
"enabled": true, "id": "190ce9f5a454493e9eaae608d54fe2d1", "parent_id": "default", "domain_id": "default", "name": "MockeyMock"}]}
'''
JSON_FULLCATALOG = '''{"token": {"is_domain": false, "methods": ["token", "password"], "roles": [{"id": "9fe2ff9ee4384b1894a90878d3e92bab", "name": "_member_"}],
"expires_at": "2017-03-28T19:13:18.000000Z", "project": {"domain": {"id": "default", "name": "Default"}, "id": "190ce9f5a454493e9eaae608d54fe2d1",
"name": "MockeyMock"}, "catalog": [{"endpoints": [{"region_id": "Region1", "url": "http://localhost:8082/api/test", "region": "Region1", "interface": "internal",
"id": "011b6db8eedd4e9d9422bdc5c29b31ed"}, {"region_id": "Region1", "url": "http://localhost:8082/api/test", "region": "Region1", "interface": "public",
"id": "4a2c135c8ddd4b28be67cbf5ddfc4e2e"}, {"region_id": "Region1", "url": "http://localhost:8082/api/test", "region": "Region1", "interface": "admin",
"id": "6fe436f7b1bb4e8c94501c262fb7a4ea"}], "type": "metering", "id": "1b91f76fd41d4ec8856ef904c7d7de5f", "name": "ceilometer"}, {"endpoints": [{"region_id": "Region1",
"url": "http://localhost:8082/api/test/keystone/v3", "region": "Region1", "interface": "public", "id": "0a34ebd757fc46318ee37552d7f58c57"}, {"region_id": "Region1",
"url": "http://localhost:8082/api/test/keystone/v3", "region": "Region1", "interface": "internal", "id": "1c953770993546ab9bf3e5b829e8b8af"}, {"region_id": "Region1",
"url": "http://localhost:8082/api/test/keystone/v3", "region": "Region1", "interface": "admin", "id": "bf70c0780b2d4904a3c1b5b526a51d7a"}], "type": "computev3",
"id": "1d995094e400496aa5eb54731aacf911", "name": "novav3"}, {"endpoints": [{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v1.1/190ce9f5a454493e9eaae608d54fe2d1",
"region": "Region1", "interface": "admin", "id": "2f9c0cf634cd4244b8a2641434fb8492"}, {"region_id": "Region1",
"url": "http://localhost:8082/api/test/keystone/v1.1/190ce9f5a454493e9eaae608d54fe2d1", "region": "Region1", "interface": "internal", "id": "352b35ef014f498a89de22ba20d32e5e"},
{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v1.1/190ce9f5a454493e9eaae608d54fe2d1", "region": "Region1", "interface": "public",
"id": "f47cab31d98d4d76aded119fe702c4c6"}], "type": "data-processing", "id": "3bff550b8b0f4e619650af43386dce58", "name": "sahara"}, {"endpoints": [{"region_id": "Region1",
"url": "http://localhost:8082/api/test/keystone", "region": "Region1", "interface": "admin", "id": "1087e53e4add4e47b2b1ce9c8d781498"}, {"region_id": "Region1",
"url": "http://localhost:8082/api/test/keystone", "region": "Region1", "interface": "internal", "id": "f6bf030cf3294e928cb17dd4edaeb3b6"}, {"region_id": "Region1",
"url": "http://localhost:8082/api/test/keystone", "region": "Region1", "interface": "public", "id": "f88f2c020a1546a3ae6f6d8abf5c56f1"}], "type": "network",
"id": "3ea76ccc58d2414f868ac02c9281a872", "name": "neutron"}, {"endpoints": [{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v1/190ce9f5a454493e9eaae608d54fe2d1",
"region": "Region1", "interface": "admin", "id": "10affb77591f495ea84c814a676b4ea7"}, {"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v1/190ce9f5a454493e9eaae608d54fe2d1",
"region": "Region1", "interface": "internal", "id": "14396392e51043cb9343bde94964033a"}, {"region_id": "Region1",
"url": "http://localhost:8082/api/test/keystone/v1/190ce9f5a454493e9eaae608d54fe2d1", "region": "Region1", "interface": "public", "id": "ad5e7d2096cd46a29d3b4abd81457076"}],
"type": "orchestration", "id": "50a8ee48ebf1462e85c0504cd8fafa63", "name": "heat"}, {"endpoints": [{"region_id": "Region1",
"url": "http://localhost:8082/api/test/keystone/v2/190ce9f5a454493e9eaae608d54fe2d1", "region": "Region1", "interface": "internal", "id": "2948061330f54fe2996d05d6467c8281"},
{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v2/190ce9f5a454493e9eaae608d54fe2d1", "region": "Region1", "interface": "public",
"id": "611099d850aa4936af46ba5a5bdb36a7"}, {"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v2/190ce9f5a454493e9eaae608d54fe2d1", "region": "Region1",
"interface": "admin", "id": "a820e9700cde4fddacdbe9be12eff6a2"}], "type": "volumev2", "id": "53b96359ef1944ed9790321cd05c7bda", "name": "cinderv2"}, {"endpoints":
[{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v1", "region": "Region1", "interface": "internal", "id": "8c94e99c01ab46f2b05522a009d9c989"},
{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v1", "region": "Region1", "interface": "admin", "id": "a40ca45719df49feac3d85dbc09ccae8"},
{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v1", "region": "Region1", "interface": "public", "id": "fb5118d119f74a21a02e5c24fa8d8808"}],
"type": "cloudformation", "id": "6ac605cbb7584b7f9e51ce03eb5c1807", "name": "heat-cfn"}, {"endpoints": [{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/services/Cloud",
"region": "Region1", "interface": "internal", "id": "d08a6919e5b34a59986fd6c87a98edf1"}, {"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/services/Admin",
"region": "Region1", "interface": "admin", "id": "db72521aa5e54bb2bae185d78b46667c"}, {"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/services/Cloud",
"region": "Region1", "interface": "public", "id": "f453dd9ca73849ae8333c4d1fcdce3ee"}], "type": "ec2", "id": "98f865505636418480ba8840d61be054", "name": "nova_ec2"},
{"endpoints": [{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v2.0", "region": "Region1", "interface": "admin", "id": "41873bb89289483380354bba7106255d"},
{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v2.0", "region": "Region1", "interface": "public", "id": "5cc6f2f9cd3f4b9bbb3fedca7a1c3644"},
{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v2.0", "region": "Region1", "interface": "internal", "id": "dab69dfe6065403ebe1a43e7cc9c6700"}],
"type": "identity", "id": "9ba7a078940141358c54dc614a048920", "name": "keystone"}, {"endpoints": [{"region_id": "Region1", "url": "http://localhost:8082/api/test/swift/v1",
"region": "Region1", "interface": "internal", "id": "678e188feb004ff783c2efd2f9f6e274"}, {"region_id": "Region1", "url": "http://localhost:8082/api/test/swift/v1",
"region": "Region1", "interface": "admin", "id": "b23e438672cd4cb9a9169bae2f5a8be9"}, {"region_id": "Region1", "url": "http://localhost:8082/api/test/swift/v1","region": "Region1",
"interface": "public", "id": "ef184b532a7e4b6296b028eff81e5070"}], "type": "object-store", "id": "a0ece720c2c84733946872fcd6d2f42b", "name": "swift"}, {"endpoints":
[{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v2/190ce9f5a454493e9eaae608d54fe2d1", "region": "Region1", "interface": "public",
"id": "805b2401424a4d6f875d509d55f21dfa"}, {"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v2/190ce9f5a454493e9eaae608d54fe2d1", "region": "Region1",
"interface": "internal", "id": "885c88e0ac574fd79da9e8f058a05bc5"}, {"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone/v2/190ce9f5a454493e9eaae608d54fe2d1",
"region": "Region1", "interface": "admin", "id": "f40b80f59eb142d89a4d0e9748999bbf"}], "type": "compute", "id": "a1fef68408714aa5bcbdcc87350a096a", "name": "nova"}, {"endpoints":
[{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone", "region": "Region1", "interface": "public", "id": "04536110ce764b5797189be3a282b724"},
{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone", "region": "Region1", "interface": "internal", "id": "306fee2ba44b4df5a801822c325deb7c"},
{"region_id": "Region1", "url": "http://localhost:8082/api/test/keystone", "region": "Region1", "interface": "admin", "id": "613697a0715f471794a3d4398f8be668"}], "type": "image",
"id": "bc9ff0e118ee4119b25f472f0817b368", "name": "glance"}, {"endpoints": [], "type": "volume", "id": "ce02b3f8b8e74d19b76732fc2046ae1a", "name": "cinder"}], "user": {"domain":
{"id": "default", "name": "Default"}, "id": "6705630a653f4300baf486a8df6072de", "name": "MockeyMock"}, "audit_ids": ["A60bVi9WQ76Blpd_g8QJEg", "aOdetpZZTBeI1NrT9m9YaQ"],
"issued_at": "2017-03-28T18:21:32.000000Z"}}
'''
JSON_AUTH = '''{"token": {"issued_at": "2017-03-27T14:33:34.000000Z", "audit_ids": ["xM40d8iLTGS-CaE70Xki7A"], "methods": ["password"], "expires_at": "2017-03-28T15:33:34.000000Z",
"user": {"domain": {"id": "default", "name": "Default"}, "id": "6705630a653f4300baf486a8df6072de", "name": "MockeyMock"}}}
'''


class MockKeystoneView(APIView):
    """
    This is the catch all view.  use this to figure out what urls/headers/json is being based in
    """

    def get(self, request):
        logger.info(" MockKeystoneView:get called")
        for header in request.META:
            logger.info("   header: %s   value %s" % (header, request.META[header]))
        return HttpResponse(JSON_404, status=status.HTTP_404_NOT_FOUND, content_type='application/json')

    def post(self, request):
        logger.info("MockKeystoneView:post called")
        logger.info(request.body)
        return HttpResponse(JSON_404, status=status.HTTP_404_NOT_FOUND, content_type='application/json')


class MockKeystoneUsersProjects(APIView):
    """
    Handles /v3/Users/<user_id>/Porjects
    """

    def get(self, request, user_id):
        logger.info(" MockKeystoneUserProjects:get called (user id: %s) " % (user_id))
        # for header in request.META:
        #    logger.info("   header: %s   value %s" % (header, request.META[header]) )
        token = request.META.get('HTTP_X_AUTH_TOKEN')
        logger.info("  token: %s" % token)
        logger.info("         %s" % EXPECTED_UNSCOPED_TOKEN)
        logger.info("  user:  %s" % user_id)
        logger.info("         %s" % EXPECTED_USER_ID)
        if token == EXPECTED_UNSCOPED_TOKEN and user_id == EXPECTED_USER_ID:
            response = HttpResponse(JSON_USERSPROJECTS, status=status.HTTP_200_OK, content_type="application/json")
            response['x-openstack-request-id'] = "req-6a536bef-af21-46a9-94e3-31f47998644f"
        elif token == EXPECTED_UNSCOPED_TOKEN:
            response = HttpResponse(JSON_403, status=status.HTTP_403_FORBIDDEN, content_type="application/json")
            response['x-openstack-request-id'] = "req-fe6bb228-537a-41f1-8e57-0b3037c0e473"
        else:
            response = HttpResponse(JSON_401, status=status.HTTP_403_FORBIDDEN, content_type="application/json")
            response['x-openstack-request-id'] = "req-fe6bb228-537a-41f1-8e57-0b3037c0e473"
        return response

    def post(self, request):
        logger.info("MockKeystoneView:post called")
        logger.info(request.body)
        return HttpResponse(JSON_404, status=status.HTTP_404_NOT_FOUND, content_type='application/json')


class MockKeystoneAuthTokens(APIView):
    """
    handles /v3/auth/tokens
    """

    def get(self, request):
        logger.info("MockKeystoneAuthToken:get called")
        for header in request.META:
            logger.info("   header: %s   value %s" % (header, request.META[header]))
        return HttpResponse(JSON_404, status=status.HTTP_404_NOT_FOUND, content_type='application/json')

    def post(self, request):
        logger.info("MockKeystoneAuthToken:post called")
        logger.info(request.body)
        ks_request = json.loads(request.body)
        token = ks_request.get('auth', {}).get('identity', {}).get('token', {}).get('id')
        # need to distinugish between token and password - note: we use scoped with token
        if token:
            if token == EXPECTED_UNSCOPED_TOKEN:
                response = HttpResponse(JSON_FULLCATALOG, status=status.HTTP_201_CREATED, content_type='application/json')
                response['X-Subject-Token'] = EXPECTED_SCOPED_TOKEN
                response['x-openstack-request-id'] = 'req-4227f7a0-4631-4014-8c70-d0bf42ff6553'
                return response
            else:
                response = HttpResponse(json_404A, status=status.HTTP_404_NOT_FOUND, content_type='application/json')
                response['x-openstack-request-id'] = 'req-4227f7a0-4631-4014-8c70-d0bf42ff6553'
                return response
        if (ks_request['auth']['identity']['password']['user']['name'] == test_settings['username']
                and ks_request['auth']['identity']['password']['user']['password'] == test_settings['password']):
            logger.info("*** success ***")
            response = HttpResponse(JSON_AUTH, status=status.HTTP_201_CREATED, content_type='application/json')
            response['x-openstack-request-id'] = 'req-4227f7a0-4631-4014-8c70-d0bf42ff6553'
            response['X-Subject-Token'] = EXPECTED_UNSCOPED_TOKEN
            return response
        else:
            logger.info("*** failed ***")
            return HttpResponse(JSON_401, status=status.HTTP_401_UNAUTHORIZED, content_type='application/json')


class MockKeystoneBaseUrl(APIView):
    """
    passes back the base URL /v3
    """

    def get(self, request):
        logger.info("MockKeystoneBaseUrl:get called")
        response = HttpResponse(JSON_BASEURL, status=status.HTTP_200_OK, content_type='application/json')
        response['x-openstack-request-id'] = 'req-3ac5dc05-785a-4a30-ba18-e13bf619767f'
        return response

    def post(self, request):
        logger.info("MockKeystoneBaseUrl:post called")
        response = HttpResponse(JSON_BASEURL, status=status.HTTP_200_OK, content_type='application/json')
        response['x-openstack-request-id'] = 'req-3ac5dc05-785a-4a30-ba18-e13bf619767f'
        return response
