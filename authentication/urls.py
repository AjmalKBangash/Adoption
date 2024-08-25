from django.urls import path
from .views import *

urlpatterns = [    
    path('custom-user/', CustomUser.as_view()),
    path('custom-user/<str:username>/', CustomUser.as_view()),
    path('simple/token/', CustomTokenObtainPairView.as_view()),
    path('refresh/token/', CustomTokenRefreshView.as_view()),
    # path('refresh/token/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('confirming-email/', ConfirmingEmail.as_view()),
    path('forgot-password/', ResetPasswordSendingEmail.as_view()),
    path('reset-password/', ResetPassword.as_view()),
    # social login function 
    path('complete-social-login/', complete_social_login, name='complete_social_login'),
]