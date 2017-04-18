# -*- coding: utf-8 -*-
# Generated by Django 1.9.8 on 2017-02-24 21:27
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0070_provider_created_by'),
    ]

    operations = [
        migrations.AddField(
            model_name='atmosphereuser',
            name='os_domain_name',
            field=models.CharField(blank=True, default=b'', max_length=500),
        ),
        migrations.AddField(
            model_name='atmosphereuser',
            name='os_user_id',
            field=models.CharField(blank=True, default=b'', max_length=500),
        ),
    ]