"""Command-line entry point for installing the Neo4j graph schema."""

import asyncio
from collections.abc import Callable

from neo4j import AsyncDriver

from threatgraph.config import Settings, get_settings
from threatgraph.graph.repository import GraphRepository, Neo4jGraphRepository
from threatgraph.infrastructure import Infrastructure

InfrastructureFactory = Callable[[Settings], Infrastructure]
RepositoryFactory = Callable[[AsyncDriver, str], GraphRepository]


async def install_graph_schema(
    settings: Settings | None = None,
    infrastructure_factory: InfrastructureFactory = Infrastructure.from_settings,
    repository_factory: RepositoryFactory = Neo4jGraphRepository,
) -> None:
    """Install graph constraints and indexes, then close all process-local clients."""

    resolved_settings = settings or get_settings()
    infrastructure = infrastructure_factory(resolved_settings)
    try:
        repository = repository_factory(
            infrastructure.neo4j,
            resolved_settings.neo4j_database,
        )
        await repository.ensure_schema()
    finally:
        await infrastructure.close()


def main() -> None:
    """Run the asynchronous schema installer from the project console script."""

    asyncio.run(install_graph_schema())
