"""Typed application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings shared by the API and asynchronous workers."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "ThreatGraph"
    app_env: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"
    postgres_dsn: SecretStr = SecretStr(
        "postgresql+asyncpg://threatgraph:threatgraph-development-only@localhost:5432/threatgraph"
    )
    neo4j_uri: str = "neo4j://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = SecretStr("threatgraph-development-only")
    neo4j_database: str = "neo4j"
    redis_url: SecretStr = SecretStr("redis://:threatgraph-development-only@localhost:6379/0")
    cors_origins: list[str] = ["http://localhost:5173"]
    health_check_timeout_seconds: float = Field(default=3.0, gt=0, le=30)


@lru_cache
def get_settings() -> Settings:
    """Return one immutable-by-convention settings instance per process."""

    return Settings()
