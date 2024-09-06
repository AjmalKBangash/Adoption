# Import Celery app to make sure it's loaded when Django starts.
from .celery_app import adoption_app as celery_app

__all__ = ('celery_app',)
