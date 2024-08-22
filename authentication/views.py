from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework.views import APIView
from rest_framework import status
from .serializers import *
from .models import CustomUser as Custom_made_User
from .models import *
from django.contrib.auth.hashers import check_password
from django.contrib.auth.hashers import make_password  # This make_password function will convert the plaintext password received from react and convert it into password hashable configured in the settings of password validators
# so without this make_password function the passwords will be saved in the plaintext in the database of django which will not recommended and which is a flaw
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes,  force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf import settings
from rest_framework.generics import  ListCreateAPIView,  RetrieveUpdateDestroyAPIView
from rest_framework import filters
from rest_framework.permissions import AllowAny,IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from .utils import UserActivation
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password



class CustomUser(ListCreateAPIView,RetrieveUpdateDestroyAPIView):
    queryset = Custom_made_User.objects.all()
    serializer_class = CustomUserSerializer
    lookup_field = 'username' 
    # filter_backends = [DjangoFilterBackend]
    filter_backends = [filters.SearchFilter]
    search_fields = ['^username', 'email']
    # def get_permissions(self):
    #     if self.request.method == 'POST':
    #         # Allow any for POST requests
    #         return [AllowAny()]
    #     else:
    #         # Use IsAuthenticated for other methods (GET, PUT, PATCH, DELETE)
    #         return [IsAuthenticated()]
    def post(self, request, *args, **kwargs):
            serializer = self.get_serializer(data = request.data)
            if serializer.is_valid():
                returned_value = UserActivation.sending_mail(serializer.data['email'])
            # if returned_value and serializer.is_valid(raise_exception=True):
            if True and serializer.is_valid(raise_exception=True):
                
                # ONE WAY TO CREATE USER  THIS IS WRON WAY
                user_creation = Custom_made_User()
                user_creation.email = serializer.data['email']
                user_creation.username = serializer.data['username']
                user_creation.password = make_password(request.data['password'])
                user_creation.is_staff = True
                user_creation.is_superuser = True
                user_creation.save()
                
                # SECOND WAY TO CREATE USER
                # user_creation = Custom_made_User.objects.create_user(
                # email=serializer.data['email'],
                # password=request.data['password'],
                # username=serializer.data['username'],
                ## phone=serializer.data['phone'],
                # profile_picture=serializer.data['profile_picture'])
                
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return  Response(data= 'Bad request',  status=status.HTTP_400_BAD_REQUEST)
    def get(self, request, username=None, *args, **kwargs):
        if username:
            # Retrieve a specific instance by email
            kwargs['username'] = username
            return self.retrieve(request._request, *args, **kwargs)
        else:
            # List all instances
            return self.list(request, *args, **kwargs) # IT NOT RETURN ALL INSTANCES WHICHIS TOTALLY WRONG IF THE USERNAME OE EMAIL IS NOOT PROVIDED
    def put(self, request, *args, **kwargs):
        instance = self.get_queryset().filter(username=kwargs.get('username')).first()
        if instance is None:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        # Create a copy of the request data
        data = request.data.copy()
        # Hash the password if provided in the request
        password = data.get('password')
        if password:
            data['password'] = make_password(password)
        # Use the copied and modified data in the update
        serializer = self.get_serializer(instance, data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        instance = self.get_queryset().filter(username=kwargs.get('username')).first()
        if instance is None:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        # Create a copy of the request data
        data = request.data.copy()
        # Hash the password if provided in the request
        password = data.get('password')
        if password:
            data['password'] = make_password(password)
        # Use the copied and modified data in the partial update
        serializer = self.get_serializer(instance, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)

    
    # def delete(self, request, *args, **kwargs):
    #     username = request.data.get('username')
    #     try:
    #         user = self.get_queryset().get(username=username)
    #     except Custom_made_User.DoesNotExist:
    #         return Response({'bad request user not found!'}, status=status.HTTP_400_BAD_REQUEST)

    #     # Check permissions (implement your own logic here)
    #     # if not request.user.has_perm('delete_user', user):  # Example permission check
    #     #     return Response({'permission denied'}, status=status.HTTP_403_FORBIDDEN)

    #     user.delete()
    #     return Response({'user deleted successfully'}, status=status.HTTP_202_ACCEPTED)

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = Custom_made_User.objects.filter(email=request.data.get('email')).first()
            if user is None:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            if check_password(request.data['password'], user.password):
                refresh = RefreshToken.for_user(user)
                if request.data.get('rememberMe') == 'true':
                    # refresh.set_exp(lifetime=timedelta(seconds=1200))
                    refresh.set_exp(lifetime=settings.REFRESH_TOKEN_LIFETIME_CUSTOM_IF_REMEMBERME_TRUE)
                return Response({'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'The password is wrong, please provide valid password'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


        
class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer   

# THIS VIEW IS FOR CONFIRMING EMAIL THROUGH POST REQUEST WE ARE ACTIVATING USER ACCOUNT AND DELETING DATA FROM Otps MODEL 
class ConfirmingEmail(APIView):
    def post(self, request, *args, **kwargs):
        try:
            user_instance_otp = Otps.objects.get(user_email = request.data.get('user_email'))
            if user_instance_otp:
                if user_instance_otp.user_otp ==  request.data.get('user_otp'):
                    user_instance = Custom_made_User.objects.get(email = request.data.get('user_email'))
                    if user_instance:
                        # user_instance.is_active = True
                        user_instance.is_confirmed = True
                        user_instance.save()
                    user_instance_otp.delete()
            return Response({'Account verified successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': 'Bad credentials'}, status=status.HTTP_400_BAD_REQUEST)
        
# THIS VIEW IS FOR RESETING PASSWORD FOR USER SENDING THEM LINK VIA EMAIL
class ResetPasswordSendingEmail(APIView):
    def post(self, request, *args, **kwargs):
        try:
            user_email = request.data.get('email')
            if user_email:
                user = Custom_made_User.objects.get(email=user_email)
                token = default_token_generator.make_token(user)
                uidb64 = urlsafe_base64_encode(force_bytes(user.email))
                frontend_app = settings.FRONTEND_APP
                reset_url = f"{frontend_app}/reset-password/{uidb64}/{token}/"
                # Prepare the HTML message with your company name
                subject = 'Password Reset Request'
                message = render_to_string('reset_password_email.html', {
                    'user': user,
                    'reset_url': reset_url,
                    'company_name': 'Allikhwa',
                })
                send_mail(
                    subject,
                    '',
                    settings.EMAIL_HOST_USER,
                    [user.email],
                    fail_silently=False,
                    html_message=message,  # Use HTML content for the email
                )
                # Render the success template html document in resposne which is not good because we want http resposne for our frontend the html response is needed when django is bot serving frontend and backend 
                # return render(request, 'password_reset_success.html', status=status.HTTP_200_OK)
                return Response({'success': "We've sent a password reset link to your email address.Please check your inbox (and spam folder, just in case) and follow the instructions to reset your password"}, status=status.HTTP_200_OK)
            else:
                raise LookupError
        except Exception as e:
            # Render the error template
            # return render(request, 'password_reset_error.html', status=status.HTTP_401_UNAUTHORIZED)
            return Response({"error": 'Please provide valid email!'}, status=status.HTTP_401_UNAUTHORIZED)

class ResetPassword(APIView):
    def post(self, request, *args, **kwargs):
        try:
            uidb64 = request.data.get('uidb64')
            user_email = force_str(urlsafe_base64_decode(uidb64))
            token = request.data.get('token')
            user = Custom_made_User.objects.get(email=str(user_email))
            password = request.data.get('password')
            # Validate the password
            try:
                validate_password(password, user)
            except ValidationError as e:
                return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)
            if default_token_generator.check_token(user, token) and user:
                user.set_password(password)
                user.save()
                return Response({'success': 'Password reset successfully'}, status=status.HTTP_202_ACCEPTED)
            else:
                return Response({'error': 'Invalid token or user!'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'Please provide valid data or recycle the process!'}, status=status.HTTP_400_BAD_REQUEST)

        

