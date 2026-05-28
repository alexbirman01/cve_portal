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
    # Route sync_plat_for_run to its own queue so a dedicated concurrency=1
    # worker processes auto-syncs sequentially without blocking process_issue.
    task_routes={
        "sync_plat_for_run": {"queue": "plat_sync"},
    },
    beat_schedule={
        "run-due-plat-syncs": {
            "task": "run_due_plat_syncs",
            "schedule": 3600.0,  # every 1 hour (24h window, no need to poll every 15 min)
        },
    },
)

# Ensure tasks are registered when the worker starts.
# (Explicit import is the most reliable option for small apps.)
import worker.app.tasks  # noqa: F401

