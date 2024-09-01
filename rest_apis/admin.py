from django.contrib import admin
from .models import PermissionCustomModel, Model001

admin.site.register(Model001)
admin.site.register(PermissionCustomModel)
