from django.urls import path
from .views import PermissionCustomModelView

urlpatterns = [    
    path('per-chk/', PermissionCustomModelView.as_view()),
]