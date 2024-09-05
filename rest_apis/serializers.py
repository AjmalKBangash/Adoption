from rest_framework.serializers import ModelSerializer
from .models import PermissionCustomModel, Model001


class Model001Serializer(ModelSerializer):
    class Meta:
        model = Model001
        fields = ['id','charr', 'textt', 'booleann', 'score', 'url', 'token', 'file', 'video']

class PermissionCustomModelSerializer(ModelSerializer):
    class Meta:
        model = PermissionCustomModel
        fields = ['name', 'permission_given', 'is_true', 'your_niece']