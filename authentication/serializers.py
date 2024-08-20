from django.contrib.auth.password_validation import validate_password
from .models import *
import re
from typing import Any, Dict
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)   
    class Meta:
        model = CustomUser
        # fields = '__all__'
        fields = ['username', 'email', 'password']  # Specify the fields you want to include

    def validate_password(self, value):
        validate_password(value)
        return value
    # def validate_password(self, value):
    #     """
    #     Check that the password is at least 7 characters long, includes letters, numbers,
    #     and at least one special character.
    #     """
    #     if len(value) < 7:
    #         raise serializers.ValidationError("Password must be at least 7 characters long.")
        
    #     if not re.search(r'[A-Za-z]', value):
    #         raise serializers.ValidationError("Password must contain at least one letter.")
        
    #     if not re.search(r'\d', value):
    #         raise serializers.ValidationError("Password must contain at least one number.")
        
    #     if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
    #         raise serializers.ValidationError("Password must contain at least one special character.")

    #     return valueer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        return super().validate(attrs)
class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, str]:
        return super().validate(attrs)    
class otpsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Otps
        fields = '__all__'