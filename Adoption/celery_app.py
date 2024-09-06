import os
from celery import Celery
from celery_prometheus_exporter import setup_metrics

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Adoption.settings')

adoption_app = Celery('Adoption')
adoption_app.config_from_object('django.conf:settings', namespace = 'CELERY')
adoption_app.autodiscover_tasks()

# PRMETHEUS FOR CELERY
setup_metrics(adoption_app)

# if __name__ == "__main__": # it should be for starting a separate process for prometheus exporter 
#     start_http_server(9002)  # Port where metrics will be exposed
#     print("Celery Prometheus exporter running on port 9002")
#     adoption_app.start()

# @adoption_app.task(bind=True)
# def debug_task(self):
#     print(f'Request: {self.request!r}')