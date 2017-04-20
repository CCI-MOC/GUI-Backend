from api.v2.views.base import AuthViewSet
from api.v2.serializers.post import ClusterSerializer

from core.models import Cluster

from core.models import AtmosphereUser, Identity
from keystoneauth1.identity import v3
from rtwo.drivers.openstack_network import NetworkManager
from rtwo.drivers.openstack_user import UserManager
from keystoneauth1 import session

class ClusterViewSet(AuthViewSet):

    """
    API endpoint that allows cluster to be viewed or edited.
    """

    queryset = Cluster.objects.all()
    serializer_class = ClusterSerializer
    model = Cluster

    def perform_create(self, serializer):
        user = self.request.user
        data = self.request.data
        plugin_name = data['pluginName']
        if plugin_name == "vanilla":
            hadoop_version = "2.7.1"
        elif plugin_name == "spark":
            hadoop_version = "1.6.0"
        elif puglin_name == "storm":
            hadoop_version = "1.0.1"
        else:
            raise Exception("Cannot find the plugin")
        name = data['clusterName']
        identity = Identity.objects.get(created_by=user)
        cred = identity.get_credentials()
        project_name = str(cred['ex_project_name'])
        auth_url = str(cred['ex_force_auth_url'])
        token = str(cred['ex_force_auth_token'])
        token_auth=v3.Token(
            auth_url=auth_url,
            token=token,
            project_name=project_name,
            project_domain_id="default")
        ses = session.Session(auth=token_auth)
        network_driver = NetworkManager(session=ses)
        user_driver = UserManager(auth_url=auth_url, auth_token=token, project_name=project_name, domain_name="default", session=ses, version='v3')
        ct = network_driver.sahara.cluster_templates.list()[0]
        kp = user_driver.nova.keypairs.list()[0]
        net_id= network_driver.neutron.list_networks()['networks'][0]['id']
        image = None
        for img in user_driver.glance.images.list():
	    if "Sahara: Vanilla 2.7.1 on Ubuntu 14.04" in img.name:
		image = img
        image_id= image.id
        network_driver.sahara.clusters.create(plugin_name=plugin_name, hadoop_version=hadoop_version, cluster_template_id=str(ct.id), default_image_id=str(image_id), user_keypair_id=str(kp.id), name=name, net_id=str(net_id))
        
        #identity = Identity.objects.get(created_by=user)
        #serializer.save(identity=identity)

    def get_queryset(self):
        """
        Filter projects by current user
        """
        user = self.request.user
        identity = Identity.objects.get(created_by=user)
        return Cluster.objects.filter(identity=identity)
