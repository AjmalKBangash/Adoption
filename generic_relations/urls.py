from django.urls import path, include
from .views import GenericRelationModelView
from rest_framework.routers import DefaultRouter
from .views import *

router = DefaultRouter()
router.register(r'generic-tag', GenericRelationModelView, basename='genericrelationmodel')

urlpatterns = [
    path('', include(router.urls)),
]