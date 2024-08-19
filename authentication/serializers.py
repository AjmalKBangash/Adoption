from .models import *
from typing import Any, Dict
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)   
    # profile_picture = serializers.ImageField()
        # validators=[FileExtensionValidator(['png', 'jpg', 'jpeg'])]  
    class Meta:
        model = CustomUser
        # fields = '__all__'
        fields = ['username', 'email', 'password']  # Specify the fields you want to include

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, str]:
        return super().validate(attrs)


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, str]:
        return super().validate(attrs)    
    
class otpsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Otps
        fields = '__all__'