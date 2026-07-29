import asyncio
from typing import cast

import pytest
from neo4j import AsyncDriver

from threatgraph.config import Settings
from threatgraph.graph import bootstrap
from threatgraph.graph.repository import GraphRepository
from threatgraph.infrastructure import Infrastructure


class FakeInfrastructure:
    def __init__(self) -> None:
        self.neo4j = cast(AsyncDriver, object())
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class FakeRepository:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.installed = False

    async def ensure_schema(self) -> None:
        if self.error:
            raise self.error
        self.installed = True


def test_install_graph_schema_uses_configured_database_and_closes_clients() -> None:
    infrastructure = FakeInfrastructure()
    repository = FakeRepository()
    received_database: list[str] = []

    def infrastructure_factory(settings: Settings) -> Infrastructure:
        assert settings.neo4j_database == "analytics"
        return cast(Infrastructure, infrastructure)

    def repository_factory(driver: AsyncDriver, database: str) -> GraphRepository:
        assert driver is infrastructure.neo4j
        received_database.append(database)
        return cast(GraphRepository, repository)

    settings = Settings(neo4j_database="analytics")
    asyncio.run(
        bootstrap.install_graph_schema(
            settings,
            infrastructure_factory,
            repository_factory,
        )
    )

    assert received_database == ["analytics"]
    assert repository.installed is True
    assert infrastructure.closed is True


def test_install_graph_schema_closes_clients_after_failure() -> None:
    infrastructure = FakeInfrastructure()
    repository = FakeRepository(RuntimeError("schema failed"))

    with pytest.raises(RuntimeError, match="schema failed"):
        asyncio.run(
            bootstrap.install_graph_schema(
                infrastructure_factory=lambda settings: cast(Infrastructure, infrastructure),
                repository_factory=lambda driver, database: cast(GraphRepository, repository),
            )
        )

    assert infrastructure.closed is True


def test_bootstrap_main_runs_async_installer(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    async def fake_install_graph_schema() -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(bootstrap, "install_graph_schema", fake_install_graph_schema)

    bootstrap.main()

    assert called is True
