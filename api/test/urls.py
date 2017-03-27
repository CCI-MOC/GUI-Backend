# -*- coding: utf-8 -*-
"""
Routes for api test endpoints
"""
from django.conf.urls import include, url
#from rest_framework import routers
from rest_framework.urlpatterns import format_suffix_patterns
from api.test import views
from api.base import views as base_views

urlpatterns = [
    url(r'^keystone/.*', views.MockKeystoneView.as_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)

#router = routers.DefaultRouter(trailing_slash=False)
#router.register(r'mock_keystone', views.MockKeystoneView)
