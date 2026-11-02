from celery import Celery
from celery.schedules import crontab

from app.config import settings

broker = settings.rabbitmq_url or settings.redis_url or "memory://"
backend = settings.redis_url or "cache+memory://"

celery_app = Celery(
    "atlas",
    broker=broker,
    backend=backend,
    include=[
        "app.workers.sbom_tasks",
        "app.workers.scan_tasks",
        "app.workers.intelligence_tasks",
        "app.workers.notification_tasks",
    ],
)

celery_app.conf.update(
    task_always_eager=settings.celery_always_eager,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=3600,
    task_soft_time_limit=3300,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "run-due-scan-schedules": {
            "task": "atlas.scans.run_scheduled",
            "schedule": crontab(minute="*"),
        },
        "refresh-notification-delivery": {
            "task": "atlas.notifications.deliver_pending",
            "schedule": crontab(minute="*/5"),
        },
    },
)
