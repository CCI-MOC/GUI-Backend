# -*- coding: utf-8 -*-
# Generated by Django 1.9.8 on 2017-04-10 19:12
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0072_auto_20170329_0727'),
    ]

    operations = [
        migrations.AddField(
            model_name='project',
            name='os_domain_id',
            field=models.CharField(blank=True, max_length=512, null=True),
        ),
        migrations.AddField(
            model_name='project',
            name='os_project_id',
            field=models.CharField(blank=True, max_length=512, null=True),
        ),
    ]