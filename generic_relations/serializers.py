from rest_framework.serializers import ModelSerializer,SerializerMethodField
from .models import GenericRelationModel
from rest_apis.models import Model001
from rest_apis.serializers import Model001Serializer

class GenericRelationModelSerializer(ModelSerializer):
    # class Meta:
    #     model = GenericRelationModel
    #     fields = ['content_type', 'object_id', 'content_object', 'description']
        
    content_object = SerializerMethodField()

    class Meta:
        model = GenericRelationModel
        fields = ['content_type', 'object_id', 'content_object', 'description']

    def get_content_object(self, obj):
        # Serialize the related object (content_object)
        if isinstance(obj.content_object, Model001):
            return Model001Serializer(obj.content_object).data
        # Add more cases here if you have other models related via GenericRelationModel
        return str(obj.content_object)  # Fallback to a string representation
        