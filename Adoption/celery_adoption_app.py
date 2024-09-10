import os
from celery import Celery, signals
from prometheus_client import start_http_server
from celery_prometheus_exporter import setup_metrics

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Adoption.settings')

adoption_app = Celery('Adoption')
adoption_app.config_from_object('django.conf:settings', namespace = 'CELERY')
adoption_app.autodiscover_tasks()

# from celery import current_app
print('llllllllllllllllllllllllllllllllllllll')
print(adoption_app.conf) # SEEING DEFAULT CONFIGURATIONS
print('llllllllllllllllllllllllllllllllllllll')

# PRMETHEUS FOR CELERY
# setup_metrics(adoption_app)

# if __name__ == "__main__": # it should be for starting a separate process for prometheus exporter 
#     start_http_server(9002)  # Port where metrics will be exposed
#     print("Celery Prometheus exporter running on port 9002")
#     adoption_app.start()

# @adoption_app.task(bind=True)
# def debug_task(self):
#     print(f'Request: {self.request!r}')


# ////////////////////////////////////////////////////////////
# # Port on which metrics will be exposed (e.g., 8000)
METRICS_PORT = 9002

def start_exporter():
    """Starts the Prometheus HTTP server to expose metrics."""
    start_http_server(METRICS_PORT)
    setup_metrics(adoption_app)

# Signal to initialize Prometheus metrics when Celery worker starts
@signals.worker_ready.connect
def worker_ready_handler(**kwargs):
    start_exporter()