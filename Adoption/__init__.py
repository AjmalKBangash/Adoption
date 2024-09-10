# Import Celery app to make sure it's loaded when Django starts.
from .celery_adoption_app import adoption_app as celery_adoption_app

__all__ = ('celery_adoption_app',)
