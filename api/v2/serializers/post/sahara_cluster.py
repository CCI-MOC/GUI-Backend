from core.models import Cluster


from rest_framework import serializers


class ClusterSerializer(serializers.Serializer):
    """
    """
    # Flags
    uuid = serializers.CharField(max_length=36, read_only=True)

    class Meta:
        model = Cluster
        fields = "__all__"
