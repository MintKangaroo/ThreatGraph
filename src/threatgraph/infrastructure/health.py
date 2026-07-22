"""Readiness probes for ThreatGraph infrastructure dependencies."""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Literal, Protocol

from pydantic import BaseModel
from sqlalchemy import text

from threatgraph.infrastructure.resources import Infrastructure


class ComponentHealth(BaseModel):
    """Sanitized status for one infrastructure dependency."""

    status: Literal["up", "down"]


class ReadinessReport(BaseModel):
    """Aggregate readiness status returned by the API."""

    status: Literal["ready", "degraded"]
    components: dict[str, ComponentHealth]


class ReadinessChecker(Protocol):
    """Interface used by the HTTP layer and replaceable in tests."""

    async def check(self) -> ReadinessReport:
        """Check all required dependencies without leaking connection details."""


class InfrastructureReadinessChecker:
    """Run bounded connectivity checks against every required data service."""

    def __init__(self, infrastructure: Infrastructure, timeout_seconds: float) -> None:
        self._infrastructure = infrastructure
        self._timeout_seconds = timeout_seconds

    async def check(self) -> ReadinessReport:
        checks = await asyncio.gather(
            self._bounded_check(self._check_postgres),
            self._bounded_check(self._check_neo4j),
            self._bounded_check(self._check_redis),
        )
        component_names = ("postgres", "neo4j", "redis")
        components = dict(zip(component_names, checks, strict=True))
        status: Literal["ready", "degraded"] = (
            "ready" if all(item.status == "up" for item in checks) else "degraded"
        )
        return ReadinessReport(status=status, components=components)

    async def _bounded_check(
        self,
        check: Callable[[], Awaitable[None]],
    ) -> ComponentHealth:
        try:
            async with asyncio.timeout(self._timeout_seconds):
                await check()
        except Exception:  # Dependency errors are deliberately collapsed at this boundary.
            return ComponentHealth(status="down")
        return ComponentHealth(status="up")

    async def _check_postgres(self) -> None:
        async with self._infrastructure.postgres.connect() as connection:
            await connection.execute(text("SELECT 1"))

    async def _check_neo4j(self) -> None:
        await self._infrastructure.neo4j.verify_connectivity()

    async def _check_redis(self) -> None:
        if not await self._infrastructure.redis.ping():
            raise ConnectionError("Redis ping returned a false response")
