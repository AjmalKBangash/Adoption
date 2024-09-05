# from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from .models import GenericRelationModel
from .serializers import GenericRelationModelSerializer
from rest_framework.viewsets import ModelViewSet


class GenericRelationModelView(ModelViewSet):
    permission_classes = [AllowAny]
    queryset = GenericRelationModel.objects.all()
    serializer_class = GenericRelationModelSerializer
    