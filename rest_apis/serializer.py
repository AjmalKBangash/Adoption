from rest_framework.serializers import ModelSerializer
from .models import PermissionCustomModel


class PermissionCustomModelSerializer(ModelSerializer):
    class Meta:
        model = PermissionCustomModel
        fields = ['name', 'permission_given', 'is_true', 'your_niece']