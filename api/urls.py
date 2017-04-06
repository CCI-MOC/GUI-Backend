# -*- coding: utf-8 -*-
"""
Top level routes for the api endpoints
"""
from django.conf.urls import url, include
from api.v2 import urls as v2_urls
from api.v1 import urls as v1_urls
from api.status import urls as status_urls
from api.test import urls as test_urls
from atmosphere.settings.local import TEST as test_settings

urlpatterns = [
    url(r'', include(v2_urls, namespace="default")),
    url(r'^v1/', include(v1_urls, namespace="v1")),
    url(r'^v2/', include(v2_urls, namespace="v2")),
    url(r'^status/', include(status_urls, namespace="status"))
]

if test_settings.get('Testing') == 1:
    urlpatterns += [url(r'^test/', include(test_urls, namespace="test"))]
