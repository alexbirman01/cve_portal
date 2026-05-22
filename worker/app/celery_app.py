from celery import Celery

from api.app.config import settings


celery_app = Celery(
    "cve_portal",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_track_started=True,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    beat_schedule={
        "run-due-plat-syncs": {
            "task": "run_due_plat_syncs",
            "schedule": 900.0,  # every 15 minutes
        },
    },
)

# Ensure tasks are registered when the worker starts.
# (Explicit import is the most reliable option for small apps.)
import worker.app.tasks  # noqa: F401

