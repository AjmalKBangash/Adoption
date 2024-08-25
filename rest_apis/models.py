from django.db import models

# Create your models here.

class PermissionCustomModel(models.Model):
    name = models.CharField(("name"), max_length=50)
    permission_given = models.CharField(("permission given"), max_length=50)
    is_true = models.BooleanField(("is true"))
    your_niece = models.CharField(("niece"), max_length=50)
    def __str__(self):
        return self.name