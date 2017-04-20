from django.db import models

from threepio import logger

from core.models import AtmosphereUser, Identity

from uuid import uuid4


class Cluster(models.Model):

    plugin_name = models.CharField(max_length=256)
    uuid = models.CharField(max_length=36, unique=True, default=uuid4)
    name  = models.CharField(max_length=256)
    identity  = models.ForeignKey(Identity)

    def __unicode__(self):
        return "%s - %s Plugin:%s" %\
            (self.identity, self.name, self.plugin_name)

    class Meta:
        db_table = "sahara_cluster"
        app_label = "core"
