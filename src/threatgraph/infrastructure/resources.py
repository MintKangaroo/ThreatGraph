"""Lifecycle management for PostgreSQL, Neo4j, and Redis clients."""

import asyncio
from dataclasses import dataclass

from neo4j import AsyncDriver, AsyncGraphDatabase
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from threatgraph.config import Settings


@dataclass(slots=True)
class Infrastructure:
    """Process-local infrastructure clients with a single shutdown boundary."""

    postgres: AsyncEngine
    neo4j: AsyncDriver
    redis: Redis

    @classmethod
    def from_settings(cls, settings: Settings) -> "Infrastructure":
        """Create lazy clients; network connectivity is checked by readiness probes."""

        postgres = create_async_engine(
            settings.postgres_dsn.get_secret_value(),
            pool_pre_ping=True,
        )
        neo4j = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password.get_secret_value()),
        )
        redis = Redis.from_url(
            settings.redis_url.get_secret_value(),
            decode_responses=True,
        )
        return cls(postgres=postgres, neo4j=neo4j, redis=redis)

    async def close(self) -> None:
        """Close all connection pools concurrently during process shutdown."""

        await asyncio.gather(
            self.postgres.dispose(),
            self.neo4j.close(),
            self.redis.aclose(),
        )
