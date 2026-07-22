from pydantic import SecretStr

from threatgraph.config import Settings, get_settings


def test_settings_have_safe_typed_defaults() -> None:
    settings = Settings()

    assert settings.app_name == "ThreatGraph"
    assert settings.api_prefix == "/api/v1"
    assert settings.health_check_timeout_seconds == 3.0
    assert isinstance(settings.postgres_dsn, SecretStr)
    assert "development-only" not in str(settings.postgres_dsn)


def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()

    assert get_settings() is get_settings()
