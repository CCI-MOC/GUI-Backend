import uuid
from unittest import skip, skipIf

from django.core.urlresolvers import reverse
from django.utils import timezone

from rest_framework.test import APIClient

from rest_framework.test import APITestCase, APIRequestFactory, force_authenticate
from api.tests.factories import (
    GroupFactory, UserFactory, AnonymousUserFactory, InstanceFactory, InstanceHistoryFactory, InstanceStatusFactory,
    ImageFactory, ApplicationVersionFactory, InstanceSourceFactory, ProviderMachineFactory, IdentityFactory, ProviderFactory,
    IdentityMembershipFactory, QuotaFactory)
from api.v2.views import InstanceViewSet
from core.models import AtmosphereUser


class InstanceTests(APITestCase):
    def setUp(self):
        self.anonymous_user = AnonymousUserFactory()
        self.user = UserFactory.create(username='test-username')
        self.provider = ProviderFactory.create()
        self.user_identity = IdentityFactory.create_identity(
            created_by=self.user,
            provider=self.provider)
        self.machine = ProviderMachineFactory.create_provider_machine(self.user, self.user_identity)
        self.active_instance = InstanceFactory.create(
            name="Instance in active",
            provider_alias=uuid.uuid4(),
            source=self.machine.instance_source,
            created_by=self.user,
            created_by_identity=self.user_identity,
            start_date=timezone.now())
        self.view = InstanceViewSet.as_view({'get': 'list'})
        factory = APIRequestFactory()
        url = reverse('api:v2:instance-list')
        self.request = factory.get(url)

    def test_is_not_public(self):
        force_authenticate(self.request, user=self.anonymous_user)
        response = self.view(self.request)
        self.assertEquals(response.status_code, 403)

    def test_response_is_paginated(self):
        force_authenticate(self.request, user=self.user)
        response = self.view(self.request)
        self.assertEquals(response.data['count'], 1)
        self.assertEquals(len(response.data.get('results')), 1)

    def test_response_contains_expected_fields(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        url = reverse('api:v2:instance-list')
        # force_authenticate(self.request, user=self.user)
        # response = self.view(self.request)
        response = client.get(url)
        data = response.data.get('results')[0]
        self.assertEquals(response.status_code, 200)
        self.assertEquals(len(data), 22, "Number of fields does not match")
