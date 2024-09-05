from django.db import models
from uuid import uuid4
from django.utils.translation import gettext_lazy as _


# WHILE DEVELOPONG MODELS IN DJANGO REMEMBER ALL THESE FIELD TYPES
# AutoField: Automatically generated unique integer field (primary key).
# BooleanField: Stores True or False values.
# CharField: Stores character data (e.g., strings).
# DateField: Stores a date.
# DateTimeField: Stores a date and time.
# DecimalField: Stores a decimal number with specified precision and scale.
# EmailField: Validates email addresses.
# FileField: Stores file paths.
# FloatField: Stores floating-point numbers.
# IntegerField: Stores integers.
# ManyToManyField: Represents many-to-many relationships between models.
# NullBooleanField: Stores True, False, or None.
# OneToOneField: Represents one-to-one relationships between models.
# PositiveIntegerField: Stores positive integers.
# SmallIntegerField: Stores small integers.
# TextField: Stores large text fields.
# TimeField: Stores a time.
# URLField: Validates URLs.
# UUIDField: Stores UUIDs.

class Model001(models.Model):
    charr = models.CharField(_("character field"), max_length=50)
    textt = models.TextField(_("text field"))
    # numberr = models.PhoneNumberField(_("phone number field"))
    booleann = models.BooleanField(_("boolean field"))
    # bolleann02 = models.NullBooleanField(_("null boolean field"))  # depricated except for historical migrations
    score = models.SmallIntegerField(choices=((1, 'Poor'), (2, 'Fair'), (3, 'Good'), (4, 'Very Good'), (5, 'Excellent')))
    url = models.URLField()
    token = models.UUIDField(default=uuid4, editable=False)
    # imagee = models.ImageField(_("Ajay Image"), upload_to='Images/', height_field=None, width_field=None, max_length=None)
    file = models.FileField(upload_to='Documents/')
    video = models.FileField(_("video field"), upload_to='Videos')
        
    def __str__(self):
        return str('Model001')

class PermissionCustomModel(models.Model):
    name = models.CharField(("name"), max_length=50)
    permission_given = models.CharField(("permission given"), max_length=50)
    is_true = models.BooleanField(("is true"))
    your_niece = models.CharField(("niece"), max_length=50)
    def __str__(self):
        return self.name