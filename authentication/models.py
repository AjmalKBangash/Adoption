from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class Allikhwa_UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        # user = self.model(email=email, **extra_fields)
        user = self.model(**extra_fields)
        user.email = email
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    # id = models.IntegerField()
    username = models.CharField(max_length=30, null=False, blank=False, unique = True) # IT SHOULD BE UNIQUE
    email = models.EmailField(unique=True, primary_key=True)
    # phone = models.CharField(max_length=14 )
    date = models.DateField(auto_now_add=True)
    is_active = models.BooleanField(("is active"), default=False)
    is_superuser = models.BooleanField(("is superuser"), default=True)
    # profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True)
    is_staff = models.BooleanField(("staff status"),default=True)
    last_login = models.DateTimeField(("last login"), blank=True, null=True)
    USERNAME_FIELD = 'email'
    objects = Allikhwa_UserManager()
    REQUIRED_FIELDS= [ 'username']
    
class Otps(models.Model):
    user_email = models.EmailField(unique = True, blank = True, null = True, editable = True)
    user_otp = models.CharField(max_length = 4, null = True, blank = True )
    
    def __str__(self):
        return f"{{'user_email': '{self.user_email}', 'user_otp': '{self.user_otp}'}}"
