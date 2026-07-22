import asyncio

from threatgraph.config import Settings
from threatgraph.infrastructure import Infrastructure


def test_infrastructure_clients_are_created_lazily_and_can_close() -> None:
    infrastructure = Infrastructure.from_settings(Settings())

    assert infrastructure.postgres.url.drivername == "postgresql+asyncpg"
    assert infrastructure.neo4j is not None
    assert infrastructure.redis is not None

    asyncio.run(infrastructure.close())
