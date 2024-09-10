from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.response import Response
from .models import PermissionCustomModel, Model001
from .serializers import PermissionCustomModelSerializer, Model001Serializer
# from django.utils.decorators import method_decorator
# from django.views.decorators.cache import cache_page
from django.core.cache import cache
from django.conf import settings

from rest_framework.permissions import IsAuthenticated, AllowAny, DjangoModelPermissions
# from oauth2_provider.contrib.rest_framework import OAuth2Authentication
# from drf_social_oauth2.authentication import SocialAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication

# ListCreateAPIView is intended for handling GET (list) and POST (create) requests for a collection of objects.
# RetrieveUpdateDestroyAPIView is intended for handling GET, PUT, PATCH, and DELETE requests for individual objects.
# Combining these in a single view will make it difficult for DRF to determine which logic to run, leading to routing and method-handling issues.
# /////////////////////////////////////////////////////////
#   0001 WAY OF CREATING VIEW FOR ALL CRUD OPERATIONS BUT WE HAVE DEFINE ALL METHODS GET,POST,PUT,PATCH,DELETE OTHERWISE IT WILL NOT WORK
# class Model001View(ListCreateAPIView, RetrieveUpdateDestroyAPIView): # IT WILL NOT WORK UNTIL YOU DEFINE TWO VIEWS FOR LISTCREATEAPIVIEW AND RERIEVEUPDATEDESTROYApiview BUT IF YOU WANT ALL CRUD OPERATION IN ONE VIEW THEN WE HAVE INHERIT MODELVIEWSET 
#     permission_classes = [AllowAny]
#     queryset = Model001.objects.all()
#     serializer_class = Model001Serializer
#     lookup_field = 'id'

# /////////////////////////////////////////////////////////
# 0002 WAY OF CREATING VIEW FOR CRUD OPERATIONS BUT SEPARATELY FOR LISTCREATE AND SEPARATELY FOR RETRIEVE,UPDATE AND DESTROY
class Model001ListView(ListCreateAPIView):
    permission_classes = [AllowAny]
    queryset = Model001.objects.all()
    serializer_class = Model001Serializer

class Model001DetailView(RetrieveUpdateDestroyAPIView):
    permission_classes = [DjangoModelPermissions] # use djangomodelpermissions only when you want to allign with django admin model-level permissions (the permissions given in django admin panel)
    queryset = Model001.objects.all()
    serializer_class = Model001Serializer
    lookup_field = 'id'
    
# /////////////////////////////////////////////////////////
# 0003 THIRD WAY OF CREATING ALL CRUD OPERATIONS AT ONCE 
# class Model001ViewSet(viewsets.ModelViewSet):  # BUT WE SHOULD USE ROUTERS FOR URLS 
#     permission_classes = [AllowAny]
#     queryset = Model001.objects.all()
#     serializer_class = Model001Serializer
#     lookup_field = 'id'

# class Model001ViewSet(viewsets.ModelViewSet): # IF CUSTOM ACTION NEEDED
#     # ... existing code ...

#     @action(detail=True, methods=['post'])
#     def custom_action(self, request, id=None):
#         instance = self.get_object()
#         # Implement your custom logic here
#         return Response({'status': 'custom action executed'})

# router = DefaultRouter()
# router.register(r'model001-view', Model001ViewSet, basename='model001')

# urlpatterns = [
#     path('', include(router.urls)),
# ]

# /////////////////////////////////////////////////////////
# 0004 WAY OF CREATING VIEW WITH ALL CRUD OPERATIONS  I LIKE THIS WAY
# class Model001APIView(APIView):
#     permission_classes = [AllowAny]

#     def get(self, request, id=None):
#         if id:
#             instance = get_object_or_404(Model001, id=id)
#             serializer = Model001Serializer(instance)
#             return Response(serializer.data)
#         else:
#             instances = Model001.objects.all()
#             serializer = Model001Serializer(instances, many=True)
#             return Response(serializer.data)

#     def post(self, request):
#         serializer = Model001Serializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def put(self, request, id):
#         instance = get_object_or_404(Model001, id=id)
#         serializer = Model001Serializer(instance, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def patch(self, request, id):
#         instance = get_object_or_404(Model001, id=id)
#         serializer = Model001Serializer(instance, data=request.data, partial=True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def delete(self, request, id):
#         instance = get_object_or_404(Model001, id=id)
#         instance.delete()
#         return Response(status=status.HTTP_204_NO_CONTENT)

CACHE_TTL = settings.CACHE_TTL
class PermissionCustomModelListView(ListCreateAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = PermissionCustomModel.objects.all()
    serializer_class = PermissionCustomModelSerializer
    lookup_field = 'id'
    
    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        else:
            return [IsAuthenticated()]
        
    # @method_decorator(cache_page(CACHE_TTL)) # IT IS NOT WORKING BECAUSE THIS IS ONLY DJANGO NOT FOR DRF
    # def get(self, request, *args, **kwargs):
    #     return self.list(request, *args, **kwargs)
    
    def list(self, request, *args, **kwargs):
        # Use the cache to store/retrieve the queryset or response data
        cache_key = 'permission_custom_model_list'
        cached_data = cache.get(cache_key)
        
        if cached_data is None:
            # If cache is empty, fetch data from the database
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            cached_data = serializer.data
            
            # Cache the serialized data
            cache.set(cache_key, cached_data, timeout=CACHE_TTL)
        
        # Return the cached data wrapped in a Response
        return Response(cached_data)

    def get_queryset(self):
        return PermissionCustomModel.objects.all()
    
class PermissionCustomModelDetailView(RetrieveUpdateDestroyAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated] 
    queryset = PermissionCustomModel.objects.all()
    serializer_class = PermissionCustomModelSerializer
    lookup_field = 'id'
    
    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        else:
            return [IsAuthenticated()]

        