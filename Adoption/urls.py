
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from .views import adoption_view

admin.site.site_header = "Ajay Administration"
admin.site.index_title = "Ajay Admin Management System"

urlpatterns = [
    path('', adoption_view, name="adoption"),
    path('admin/', admin.site.urls),
    path('authentication/', include('authentication.urls')),
    path('generic_relations/', include('generic_relations.urls')),  
    path('rest_apis/', include('rest_apis.urls')),  
]

if settings.DEBUG == True :
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
