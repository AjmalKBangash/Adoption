import os
from celery import Celery
from celery_prometheus_exporter import setup_metrics
from prometheus_client import start_http_server
import time

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Adoption.settings')
# Initialize Celery
app = Celery('Adoption')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# Set up Prometheus metrics for Celery
setup_metrics(app)

if __name__ == "__main__":
    start_http_server(9002)  # Port where metrics will be exposed
    print("Celery Prometheus exporter running on port 9002")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exporter stopped by user.")
    # app.worker_main()  # Start Celery workers it should be starting with command line which is >>> celery -A Adoption worker --loglevel=info
    
    

# Why Not Start Celery Workers in exporter.py?

# Starting Celery workers within the exporter.py script can lead to complications and is not recommended.
# It's better to run the Prometheus exporter and Celery workers as separate processes to keep concerns separated and make debugging easier.
