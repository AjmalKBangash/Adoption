from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from .models import PermissionCustomModel
from .serializer import PermissionCustomModelSerializer

from rest_framework.permissions import IsAuthenticated
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
# from drf_social_oauth2.authentication import SocialAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication

class PermissionCustomModelView(ListCreateAPIView, RetrieveUpdateDestroyAPIView):
    authentication_classes = [JWTAuthentication, OAuth2Authentication]
    permission_classes = [IsAuthenticated]
    queryset = PermissionCustomModel.objects.all()
    serializer_class = PermissionCustomModelSerializer

        