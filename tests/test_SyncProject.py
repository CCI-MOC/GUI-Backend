from django.test import TestCase, LiveServerTestCase
from core.models import AtmosphereUser as User
from core.models.group import Group, get_user_group
from core.models import Project
from core.models import Provider
from core.models import PlatformType
from core.models import ProviderType

from threepio import logger

from atmosphere import settings
from atmosphere.settings.local import AUTHENTICATION as auth_settings
from atmosphere.settings.local import TEST as test_settings

import requests
import time


# This is assuming a clean database
class SyncProject(LiveServerTestCase):
    username = test_settings['username']
    password = test_settings['password']

    def _setup_provider(self):
        # Need to set up the default provider
        kvm = PlatformType.objects.get_or_create(name='KVM')[0]
        openstack_type = ProviderType.objects.get_or_create(name='OpenStack')[0]
        MOC = Provider.objects.get_or_create(
            location="MOC-Test",
            description="MOC-Test",
            virtualization=kvm,
            type=openstack_type,
            public=True)[0]
        MOC.cloud_config = \
            '{"user": {"domain": "default", "secret": "012345678901234567890123456789012",'\
            ' "user_role_name": "_member_", "admin_role_name": "admin"},'\
            ' "deploy": {"hostname_format": "%(one)s.%(two)s.%(three)s.%(four)s"},'\
            ' "network": {"topology": "External Network Topology",'\
            '     "dns_nameservers": ["8.8.8.8", "8.8.4.4"],'\
            '     "default_security_rules": [["ICMP", -1, -1], ["UDP", 20, 20], ["TCP", 20, 21], ["TCP", 22, 23],'\
            '         ["UDP", 22, 23], ["TCP", 80, 80], ["TCP", 115, 115], ["TCP", 389, 389],'\
            '         ["UDP", 389, 389], ["TCP", 443, 443], ["TCP", 636, 636],'\
            '         ["UDP", 636, 636], ["TCP", 1024, 4199], ["UDP", 1024, 4199],'\
            '         ["TCP", 4201, 65535], ["UDP", 4201, 65535],'\
            '         ["TCP", 4200, 4200, "128.196.0.0/16"], ["UDP", 4200, 4200, "128.196.0.0/16"],'\
            '         ["TCP", 4200, 4200, "150.135.0.0/16"], ["UDP", 4200, 4200, "150.135.0.0/16"],'\
            '         ["TCP", 4200, 4200, "149.165.238.0/24"], ["UDP", 4200, 4200, "149.165.238.0/24"],'\
            '         ["TCP", 4200, 4200, "129.114.104.5/32"], ["UDP", 4200, 4200, "129.114.104.5/32"]]'\
            '  }'\
            '}'
        MOC.save()
        MOC.providercredential_set.get_or_create(key='region_name', value='MOC_Engage1')
        MOC.providercredential_set.get_or_create(key='network_name', value='public')
        MOC.providercredential_set.get_or_create(key='ex_force_auth_version', value='3.x_password')
        MOC.providercredential_set.get_or_create(key='auth_url', value=auth_settings['KEYSTONE_SERVER'])
        MOC.providercredential_set.get_or_create(key='public_routers', value='public_router')

    def setUp(self):
        self._setup_provider()

    # Thses not strictly a unit test, but it is a test of API and the configuration
    # Assume that auth_settings.authBackends.OpenstakLogin is being used.
    # Since we are using the OpenstackLoginBackend, there is no need to override this setting

    def test_openstack_SyncProject(self):
        logger.info("Auth Test: test to see if Test.username/Test.password can log into Openstack")
        data = {
            'username': self.username,
            'password': self.password,
            'auth_url': "localhost"
        }
        user = User.objects.filter(username=self.username)
        if len(user) > 0:
            logger.info("    username exists - non-empty database - test still OK")
        response = self.client.post("/auth", data)
        self.assertEquals(response.status_code, 201)
        resp_data = response.data
        self.assertTrue(resp_data['username'] == self.username)
        self.assertTrue(resp_data['token'] is not None)
        # should also include some database checks to ensure the account was created.
        user = User.objects.filter(username=self.username)
        self.assertTrue(user[0])
        if user[0]:
            logger.info("    Atm user: %s" % user[0].username)
            self.assertTrue(user[0].username == self.username)
            # now check for the projects
            project = Project.objects.all()
            logger.info("Project: ")
            logger.info(repr(project))
            logger.info("test projects: ")
            logger.info(repr(test_settings.get('Projects', [])[0]))
            logger.info(project[0].name in test_settings.get('Projects', []))
            self.assertTrue(project[0].name in test_settings.get('Projects', []))
            self.assertTrue(project[1].name in test_settings.get('Projects', []))
            logger.info("    PASSED")
        else:
            logger.info("    FAILED")
