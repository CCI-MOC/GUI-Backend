from api.v2.views.base import AuthViewSet
from api.v2.serializers.post import JobSerializer

from core.models import Job 

from core.models import AtmosphereUser, Identity
from keystoneauth1.identity import v3
from rtwo.drivers.openstack_network import NetworkManager
from rtwo.drivers.openstack_user import UserManager
from keystoneauth1 import session

class JobViewSet(AuthViewSet):

    """
    API endpoint that allows cluster to be viewed or edited.
    """

    queryset = Job.objects.all()
    serializer_class = JobSerializer
    model = Job 

    def perform_create(self, serializer):
        user = self.request.user
        data = self.request.data
        type_name = data['typeName']
        name = data['jobName']
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
        raise Exception("To be implemented")
        #identity = Identity.objects.get(created_by=user)
        #serializer.save(identity=identity)

    def get_queryset(self):
        """
        Filter projects by current user
        """
        user = self.request.user
        identity = Identity.objects.get(created_by=user)
        return Job.objects.filter(identity=identity)
