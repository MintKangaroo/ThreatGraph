from pydantic import SecretStr

from threatgraph.config import Settings
from threatgraph.worker.celery_app import create_celery_app


def test_celery_uses_redis_and_json_only_serialization() -> None:
    settings = Settings(redis_url=SecretStr("redis://:development-only@redis:6379/3"))

    application = create_celery_app(settings)

    assert application.conf.broker_url == "redis://:development-only@redis:6379/3"
    assert application.conf.result_backend == "redis://:development-only@redis:6379/3"
    assert application.conf.accept_content == ["json"]
    assert application.conf.task_serializer == "json"
    assert application.conf.timezone == "UTC"
