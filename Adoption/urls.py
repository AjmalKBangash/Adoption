
from django.urls import path, include
from django.contrib import admin
from django.urls import re_path
from django.conf import settings
from django.conf.urls.static import static
from .views import adoption_view
# PROMETHEUS 
from prometheus_client import multiprocess, generate_latest
from django.http import HttpResponse



admin.site.site_header = "Ajay Administration"
admin.site.index_title = "Ajay Admin Management System"

# PROMETHEUS 
def prometheus_metrics(request):
    metrics_data = generate_latest()
    return HttpResponse(metrics_data, content_type='text/plain')

app_name = "social"

urlpatterns = [
    path('', adoption_view, name="adoption"),
    path('admin/', admin.site.urls),
    # re_path(r'^auth/', include('drf_social_oauth2.urls', namespace='drf')),
    # re_path(r'^auth/', include('social_django.urls', namespace='social')),
    path('authentication/', include('authentication.urls')),
    path('generic-relations/', include('generic_relations.urls')),  
    path('rest-apis/', include('rest_apis.urls')),  
    # PROMETHEUS
    path('metrics/', prometheus_metrics, name='prometheus_metrics'),
]


# urlpatterns = patterns(
#     ...
#     re_path(r'^auth/', include('drf_social_oauth2.urls', namespace='drf'))
# )

if settings.DEBUG == True :
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
