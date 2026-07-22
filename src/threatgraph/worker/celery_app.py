"""Celery application used by ingestion and correlation workers."""

from celery import Celery

from threatgraph.config import Settings, get_settings


def create_celery_app(settings: Settings | None = None) -> Celery:
    """Create a JSON-only Celery application backed by Redis."""

    resolved_settings = settings or get_settings()
    redis_url = resolved_settings.redis_url.get_secret_value()
    application = Celery("threatgraph", broker=redis_url, backend=redis_url)
    application.conf.update(
        accept_content=["json"],
        broker_connection_retry_on_startup=True,
        enable_utc=True,
        result_serializer="json",
        task_default_queue="threatgraph",
        task_serializer="json",
        task_track_started=True,
        timezone="UTC",
    )
    return application


celery_app = create_celery_app()
