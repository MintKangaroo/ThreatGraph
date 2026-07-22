import asyncio
from typing import Any, cast

from neo4j import AsyncDriver
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from threatgraph.infrastructure import Infrastructure
from threatgraph.infrastructure.health import InfrastructureReadinessChecker


class FakeConnection:
    async def execute(self, statement: Any) -> None:
        assert str(statement) == "SELECT 1"


class FakeConnectionContext:
    async def __aenter__(self) -> FakeConnection:
        return FakeConnection()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> None:
        return None


class FakePostgres:
    def connect(self) -> FakeConnectionContext:
        return FakeConnectionContext()


class FakeNeo4j:
    def __init__(self, error: Exception | None = None, delay: float = 0) -> None:
        self.error = error
        self.delay = delay

    async def verify_connectivity(self) -> None:
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error


class FakeRedis:
    def __init__(self, response: bool = True) -> None:
        self.response = response

    async def ping(self) -> bool:
        return self.response


def make_infrastructure(
    neo4j: FakeNeo4j | None = None,
    redis: FakeRedis | None = None,
) -> Infrastructure:
    return Infrastructure(
        postgres=cast(AsyncEngine, FakePostgres()),
        neo4j=cast(AsyncDriver, neo4j or FakeNeo4j()),
        redis=cast(Redis, redis or FakeRedis()),
    )


def test_all_components_are_ready() -> None:
    report = asyncio.run(InfrastructureReadinessChecker(make_infrastructure(), 1).check())

    assert report.status == "ready"
    assert all(component.status == "up" for component in report.components.values())


def test_dependency_errors_are_sanitized() -> None:
    infrastructure = make_infrastructure(neo4j=FakeNeo4j(error=RuntimeError("secret host")))

    report = asyncio.run(InfrastructureReadinessChecker(infrastructure, 1).check())

    assert report.status == "degraded"
    assert report.components["neo4j"].status == "down"
    assert "secret host" not in report.model_dump_json()


def test_false_redis_ping_marks_readiness_degraded() -> None:
    infrastructure = make_infrastructure(redis=FakeRedis(response=False))

    report = asyncio.run(InfrastructureReadinessChecker(infrastructure, 1).check())

    assert report.status == "degraded"
    assert report.components["redis"].status == "down"


def test_slow_dependency_is_bounded_by_timeout() -> None:
    infrastructure = make_infrastructure(neo4j=FakeNeo4j(delay=0.05))

    report = asyncio.run(InfrastructureReadinessChecker(infrastructure, 0.001).check())

    assert report.status == "degraded"
    assert report.components["neo4j"].status == "down"
