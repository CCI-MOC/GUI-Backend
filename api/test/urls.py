# -*- coding: utf-8 -*-
"""
Routes for api test endpoints
"""
from django.conf.urls import include, url
from rest_framework.urlpatterns import format_suffix_patterns
from api.test import views
from api.base import views as base_views

urlpatterns = [
    url(r'^keystone/v3$', views.MockKeystoneBaseUrl.as_view()),
    url(r'^keystone/v3/auth/tokens$', views.MockKeystoneAuthTokens.as_view()),
    url(r'^keystone/v3/users/(?P<user_id>[0-9A-Za-z]+)/projects$', views.MockKeystoneUsersProjects.as_view()),
    url(r'^keystone*', views.MockKeystoneView.as_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)
