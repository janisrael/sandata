"""
Celery worker configuration for async scanning
"""
from celery import Celery
import os

def make_celery(app=None):
    """Create Celery instance"""
    broker = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    backend = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')
    
    celery = Celery(
        'security_tester',
        broker=broker,
        backend=backend
    )
    
    if app:
        celery.conf.update(app.config)
        
        class ContextTask(celery.Task):
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return self.run(*args, **kwargs)
        
        celery.Task = ContextTask
    
    return celery

# Create celery instance
celery = make_celery()

