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
import jwt
from jwt import algorithms
import requests
from django.shortcuts import redirect
from django.contrib.auth import login
# from django.contrib.auth.models import User   # IT IS NOW UPDATED WITH CUSTOM USER CREATED BY ME WHICH IS . AUTHENTICATION.MODELS.PY FILE
from django.http import HttpResponseBadRequest
import os
from decouple import config



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
                # WE ARE CALLING .delay (when delay called it is sending this task to asynchronous queue for handling and making django process free to handle other tasks) BECAUSE WE ARE LEVERAGING THE HELP OF CELERY FOR SENDING EMAIL TASK WHICH WILL BE HANDLED BY CELERY 
                returned_value = UserActivation.delay.sending_mail(serializer.data['email'])
            # if returned_value and serializer.is_valid(raise_exception=True):
            if True and serializer.is_valid(raise_exception=True):
                
                # ONE WAY TO CREATE USER  THIS IS recommended WAY because we are leveraging the help of serializer for this function
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


# /////////////////////////////////////////////////////////////////////////////////////////
# MANUALLY AUTHORIZATION USER AND THEN ADDING IT TO USER MODEL (OAUTH AUTHORIZATIONA AND AUTHENTICATION)
# REMAINING TASK 001 IS TAHT ADD ANOTHER MODEL WHERE WE CAN FIND THAT USER HAS BEEN REGISTERED FROM WHICH SOCIAL BACKEND THROUGH GOOGLE, FACEBOOK, GITHUB, LINKEDIN ETC
# REMAINING TASK 002 IS THAT ALLIGN ALL THIS LOGIC WITH RESTful APIs (DRF) AND (DRF-SIMPLEJWT) SO THAT CAN SEEMLESSLY GET TOKENS FOR APIs ACCESSIBILITY 

GOOGLE_CLIENT_ID =  os.getenv('GOOGLE_CLIENT_ID', config('GOOGLE_CLIENT_ID'))
GOOGLE_CLIENT_SECRET =  os.getenv('GOOGLE_CLIENT_SECRET', config('GOOGLE_CLIENT_SECRET'))
REDIRECT_URI_GOOGLE = os.getenv('REDIRECT_URI_GOOGLE', config('REDIRECT_URI_GOOGLE'))

# THIS IS THROUGH ACCESS_TOKEN ONLY NOT LEVERAING THE HELP OF ID_TOKEN FOR USER INTEGRITY AND AUTHENTICITY 
# def google_login(request):
#     # Step 1: Redirect user to Google's OAuth 2.0 server to initiate the authentication and authorization process.
#     google_auth_url = (
#         f"https://accounts.google.com/o/oauth2/v2/auth"
#         f"?response_type=code"
#         f"&client_id={GOOGLE_CLIENT_ID}"
#         f"&redirect_uri={REDIRECT_URI_GOOGLE}"
#         f"&scope=openid%20email%20profile"
#         f"&access_type=offline"
#         f"&prompt=consent"
#     )
#     return redirect(google_auth_url)

# def google_callback(request):
#     # Step 2: Handle the callback from Google with the authorization code.
#     code = request.GET.get('code')
#     if not code:
#         return HttpResponseBadRequest('No code returned from Google.')

#     # Step 3: Exchange the authorization code for an access token.
#     token_url = "https://oauth2.googleapis.com/token"
#     token_data = {
#         'code': code,
#         'client_id': GOOGLE_CLIENT_ID,
#         'client_secret': GOOGLE_CLIENT_SECRET,
#         'redirect_uri': REDIRECT_URI_GOOGLE,
#         'grant_type': 'authorization_code',
#     }
#     token_response = requests.post(token_url, data=token_data)
#     token_json = token_response.json()

#     if 'access_token' not in token_json:
#         return HttpResponseBadRequest('Failed to obtain access token.')

#     access_token = token_json['access_token']
#     id_token = token_json['id_token']

#     # Step 4: Use the access token to get user info.
#     user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
#     user_info_response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})
#     user_info = user_info_response.json()
#     print('////////////////////////////////////////////////////////////////////// user nfo //////////////////////////////////////////')
#     print(user_info)

#     # Step 5: Extract user information and authenticate the user.
#     email = user_info.get('email')
#     if not email:
#         return HttpResponseBadRequest('Failed to get user email.')

#     # Step 6: Authenticate or create the user in Django.
#     # user, created = User.objects.get_or_create(username=email, defaults={'email': email, 'first_name': user_info.get('given_name'), 'last_name': user_info.get('family_name')})
#     user, created = Custom_made_User.objects.get_or_create(username=email, defaults={'email': email, 'first_name': user_info.get('given_name'), 'last_name': user_info.get('family_name')})
#     if created:
#         print('hfghfjhgfghfghfhgfhgfjhgfjhgfhgfjhgfghfghfghbvcbcbnvcbnvcbnvcbnvcnbcnbvcbnv')
#         print('created')
#         print(created)
#         # Optionally, set a password for the user.
#         user.set_unusable_password()
#         user.save()

#     # Step 7: Log the user in.
#     login(request, user)

#     # Step 8: Redirect the user to the home page or any other page.
#     return redirect('/')

# THIS IS USING ----ACCESS_TOKEN ----ID_TOKEN ----TOKEN EXPIRATION LOGIC (TOKEN EXPIRATION LOGIC IS ONLY NEEDED IF USER IS MAKING API REQUESTS TO GOOGLE DUE TO MY DJANGO APP IS USING GOOGLE SERVICES)

# Get Google's public keys for JWT signature verification
def get_google_public_keys():
    jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
    jwks = requests.get(jwks_url).json()
    keys = {}
    for key in jwks['keys']:
        kid = key['kid']
        keys[kid] = algorithms.RSAAlgorithm.from_jwk(key)
    return keys

# Initiate Google login
def google_login(request):
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI_GOOGLE}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&state={request.session.session_key}"
        f"&access_type=offline"  # Request refresh token
    )
    return redirect(google_auth_url)

# Google OAuth callback
def google_callback(request):
    code = request.GET.get('code')
    if not code:
        return HttpResponseBadRequest('No code returned from Google.')

    token_url = "https://oauth2.googleapis.com/token"
    user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    token_params = {
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': REDIRECT_URI_GOOGLE,
    }
    token_response = requests.post(token_url, data=token_params)
    token_json = token_response.json()

    if 'id_token' not in token_json:
        return HttpResponseBadRequest('Failed to obtain ID token.')

    id_token = token_json['id_token']
    access_token = token_json.get('access_token')
    # refresh_token = token_json.get('refresh_token')
    # expires_in = token_json.get('expires_in')
    
    if id_token:
        try:
            unverified_header = jwt.get_unverified_header(id_token)
            kid = unverified_header['kid']

            public_keys = get_google_public_keys()
            public_key = public_keys.get(kid)
            if public_key is None:
                return HttpResponseBadRequest('Public key not found.')

            decoded_id_token = jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=GOOGLE_CLIENT_ID,
            )

            email = decoded_id_token.get('email')
            first_name = decoded_id_token.get('given_name')
            last_name = decoded_id_token.get('family_name')
        except jwt.ExpiredSignatureError:
            if 'access_token' not in token_json:
                return HttpResponseBadRequest('Failed to obtain access token.')
            user_info = user_info_response.json()
            email = user_info.get('email')
            first_name = user_info.get('given_name')
            last_name = user_info.get('family_name')
            if not email:
                return HttpResponseBadRequest('Failed to get user email.')
            # return HttpResponseBadRequest('ID Token has expired.')
        except jwt.InvalidTokenError:
            if 'access_token' not in token_json:
                return HttpResponseBadRequest('Failed to obtain access token.')
            user_info_response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})
            user_info = user_info_response.json()
            email = user_info.get('email')
            first_name = user_info.get('given_name')
            last_name = user_info.get('family_name')
            if not email:
                return HttpResponseBadRequest('Failed to get user email.')
            # return HttpResponseBadRequest('Invalid ID Token.')

    user, created = Custom_made_User.objects.get_or_create(
        username=first_name + ' ' + last_name, 
        defaults={'email': email, 'first_name': first_name, 'last_name': last_name}
    )
    if created:
        user.set_unusable_password()
        user.save()

    login(request, user)

    # Store the access token, expiration time, and refresh token securely (the code here is only needed for token managemnet)
    # expiration_time = time.time() + expires_in
    # request.session['access_token'] = access_token
    # request.session['expiration_time'] = expiration_time
    # if refresh_token:
    #     request.session['refresh_token'] = refresh_token

    return redirect('/')

# Refresh Google access token using the refresh token
# def refresh_google_access_token(refresh_token):
#     token_url = "https://oauth2.googleapis.com/token"
#     token_params = {
#         'client_id': GOOGLE_CLIENT_ID,
#         'client_secret': GOOGLE_CLIENT_SECRET,
#         'refresh_token': refresh_token,
#         'grant_type': 'refresh_token',
#     }
#     token_response = requests.post(token_url, data=token_params)
#     token_json = token_response.json()

#     if 'access_token' in token_json:
#         return token_json['access_token'], token_json['expires_in']
#     else:
#         raise Exception("Failed to refresh access token")

# # Check if the token is expired
# def is_token_expired(expiration_time):
#     return time.time() > expiration_time

# # Example protected view that checks for token expiration
# def some_protected_view(request):
#     access_token = request.session.get('access_token')
#     expiration_time = request.session.get('expiration_time')
#     refresh_token = request.session.get('refresh_token')

#     if is_token_expired(expiration_time):
#         if refresh_token:
#             try:
#                 access_token, expires_in = refresh_google_access_token(refresh_token)
#                 expiration_time = time.time() + expires_in
#                 request.session['access_token'] = access_token
#                 request.session['expiration_time'] = expiration_time
#             except Exception as e:
#                 return HttpResponseBadRequest(str(e))
#         else:
#             return redirect('/oauth/google/login/')  # Redirect to login if no refresh token is available

#     # Proceed with using the valid access token
#     api_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
#     headers = {'Authorization': f'Bearer {access_token}'}
#     response = requests.get(api_url, headers=headers)
#     user_info = response.json()

#     return HttpResponse(f'Hello, {user_info["name"]}!')


# ////////////////////////////////////////////////////////////////////////// NOW FOR FACEBOOK 

FACEBOOK_CLIENT_ID = os.getenv('FACEBOOK_CLIENT_ID', config('FACEBOOK_CLIENT_ID'))
FACEBOOK_CLIENT_SECRET = os.getenv('FACEBOOK_CLIENT_SECRET', config('FACEBOOK_CLIENT_SECRET'))
REDIRECT_URI_FACEBOOK = os.getenv('REDIRECT_URI_FACEBOOK', config('REDIRECT_URI_FACEBOOK'))


# THIS IS THROUGH ACCESS_TOKEN ONLY ACCESS_TOKEN IS FOR AUTHORIZATION
# def facebook_login(request):
#     # Step 1: Redirect user to Facebook's OAuth 2.0 server to initiate the authentication and authorization process.
#     facebook_auth_url = (
#         f"https://www.facebook.com/v13.0/dialog/oauth"
#         f"?client_id={FACEBOOK_CLIENT_ID}"
#         f"&redirect_uri={REDIRECT_URI_FACEBOOK}"
#         f"&state={request.session.session_key}"
#         f"&scope=email,public_profile"
#     )
#     return redirect(facebook_auth_url)

# def facebook_callback(request):
#     # Step 2: Handle the callback from Facebook with the authorization code.
#     code = request.GET.get('code')
#     if not code:
#         return HttpResponseBadRequest('No code returned from Facebook.')

#     # Step 3: Exchange the authorization code for an access token.
#     token_url = "https://graph.facebook.com/v13.0/oauth/access_token"
#     token_params = {
#         'client_id': FACEBOOK_CLIENT_ID,
#         'redirect_uri': REDIRECT_URI_FACEBOOK,
#         'client_secret': FACEBOOK_CLIENT_SECRET,
#         'code': code,
#     }
#     token_response = requests.get(token_url, params=token_params)
#     token_json = token_response.json()
    

#     if 'access_token' not in token_json:
#         return HttpResponseBadRequest('Failed to obtain access token.')

#     access_token = token_json['access_token']

#     # Step 4: Use the access token to get user info from Facebook.
#     user_info_url = "https://graph.facebook.com/me"
#     user_info_params = {
#         'fields': 'id,name,email,first_name,last_name',
#         'access_token': access_token,
#     }
#     user_info_response = requests.get(user_info_url, params=user_info_params)
#     user_info = user_info_response.json()
#     print('faceboook----////////////////////////////////////////////////////////////////////// user nfo //////////////////////////////////////////')
#     print(user_info)

#     if 'email' not in user_info:
#         return HttpResponseBadRequest('Failed to get user email.')

#     # Step 5: Extract user information and authenticate the user.
#     email = user_info.get('email')
#     if not email:
#         return HttpResponseBadRequest('Failed to get user email.')

#     # Step 6: Authenticate or create the user in Django.
#     user, created = Custom_made_User.objects.get_or_create(username=email, defaults={'email': email, 'first_name': user_info.get('first_name'), 'last_name': user_info.get('last_name')})
#     if created:
#         print('facebook-----hfghfjhgfghfghfhgfhgfjhgfjhgfhgfjhgfghfghfghbvcbcbnvcbnvcbnvcbnvcnbcnbvcbnv')
#         print('created')
#         print(created)
#         # Optionally, set a password for the user.
#         user.set_unusable_password()
#         user.save()

#     # Step 7: Log the user in.
#     login(request, user)

#     # Step 8: Redirect the user to the home page or any other page.
#     return redirect('/')


# THIS IS THROUGH ID_TOKEN(OPENID CONNECT (OAUTH 2.0 WITH SOME EXTRS CAPABILITIES)) ID_TOKEN IS FOR AUTHENTICATION AND IF ID_TOKEN IS INVALID OR EXPIRE WHATSOEVER THEN IT WILL LEVERAGE THE HELP OF ACCESS_TOKEN
def get_facebook_public_key(kid):
    # Fetch the public keys from Facebook
    jwks_url = "https://www.facebook.com/.well-known/oauth/openid/jwks/"
    jwks = requests.get(jwks_url).json()

    # Find the correct key using the 'kid' (key ID)
    for key in jwks['keys']:
        if key['kid'] == kid:
            return algorithms.RSAAlgorithm.from_jwk(key)
    return None

def facebook_login(request):
    facebook_auth_url = (
        f"https://www.facebook.com/v13.0/dialog/oauth"
        f"?client_id={FACEBOOK_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI_FACEBOOK}"
        f"&state={request.session.session_key}"
        f"&scope=email,public_profile"
        f"&response_type=code,token,id_token"
        f"&nonce={request.session.session_key}"  # Adding a nonce for security
    )
    return redirect(facebook_auth_url)

def facebook_callback(request):
    code = request.GET.get('code')
    if not code:
        return HttpResponseBadRequest('No code returned from Facebook.')

    token_url = "https://graph.facebook.com/v13.0/oauth/access_token"
    token_params = {
        'client_id': FACEBOOK_CLIENT_ID,
        'redirect_uri': REDIRECT_URI_FACEBOOK,
        'client_secret': FACEBOOK_CLIENT_SECRET,
        'code': code,
    }
    token_response = requests.get(token_url, params=token_params)
    token_json = token_response.json()

    if 'access_token' not in token_json:
        return HttpResponseBadRequest('Failed to obtain access token.')

    access_token = token_json['access_token']
    id_token = token_json.get('id_token')

    if id_token:
        try:
            # Decode the header of the ID token to get the key ID (kid)
            unverified_header = jwt.get_unverified_header(id_token)
            kid = unverified_header['kid']

            # Get the public key that matches the kid
            public_key = get_facebook_public_key(kid)
            if public_key is None:
                return HttpResponseBadRequest('Public key not found.')

            # Verify the ID token using the public key
            decoded_id_token = jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=FACEBOOK_CLIENT_ID,  # Ensure the token is intended for your app
            )

            email = decoded_id_token.get('email')
            first_name = decoded_id_token.get('given_name')
            last_name = decoded_id_token.get('family_name')
        except jwt.ExpiredSignatureError:
            return HttpResponseBadRequest('ID Token has expired.')
        except jwt.InvalidTokenError:
            return HttpResponseBadRequest('Invalid ID Token.')

    # Fallback to access token if ID token isn't provided
    if not id_token:
        user_info_url = "https://graph.facebook.com/me"
        user_info_params = {
            'fields': 'id,name,email,first_name,last_name',
            'access_token': access_token,
        }
        user_info_response = requests.get(user_info_url, params=user_info_params)
        user_info = user_info_response.json()

        if 'email' not in user_info:
            return HttpResponseBadRequest('Failed to get user email.')

        email = user_info.get('email')
        first_name = user_info.get('first_name')
        last_name = user_info.get('last_name')

    user, created = Custom_made_User.objects.get_or_create(
        username=first_name + ' ' + last_name, 
        defaults={'email': email, 'first_name': first_name, 'last_name': last_name}
    )
    if created:
        user.set_unusable_password()
        user.save()

    login(request, user)
    return redirect('/')



        

