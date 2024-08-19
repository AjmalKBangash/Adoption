from django.contrib import admin
from .models import *

class CustomUserAdmin(admin.ModelAdmin):
    def save_model(self, request, obj, form, change):
        obj.set_password(obj.password)
        return super().save_model(request, obj, form, change)
admin.site.register(CustomUser, CustomUserAdmin)

class OtpsAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'user_otp')
admin.site.register(Otps, OtpsAdmin)
