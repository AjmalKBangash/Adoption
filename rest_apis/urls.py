from django.urls import path
from .views import PermissionCustomModelListView, PermissionCustomModelDetailView, Model001ListView, Model001DetailView

urlpatterns = [    
    path('model001-view/', Model001ListView.as_view()),
    path('model001-view/<int:id>/', Model001DetailView.as_view()),
    path('per-chk/', PermissionCustomModelListView.as_view()),
    path('per-chk/<int:id>/', PermissionCustomModelDetailView.as_view()),
]