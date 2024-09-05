from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey

class GenericRelationModel(models.Model):  # NOW WE CAN TAG THS GENERIC RELATION TO ANY MODEL IN ANY APP IN DJANGO PROJECT 
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')
    description = models.TextField()

    def __str__(self):
        return f"{self.content_type} - {self.object_id}"
 
class Likes(models.Model):
    like_name = models.CharField( max_length=50)
    
class LikedItem(models.Model):
    like = models.ForeignKey(Likes, on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey()