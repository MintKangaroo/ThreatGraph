import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, TypeVar, cast
from uuid import UUID

import pytest
from neo4j import AsyncDriver, AsyncManagedTransaction
from neo4j.time import DateTime as Neo4jDateTime

from threatgraph.graph.models import (
    EntityCreate,
    EntityType,
    GraphEntity,
    GraphRelationship,
    RelationshipCreate,
    RelationshipType,
)
from threatgraph.graph.repository import GraphIntegrityError, Neo4jGraphRepository
from threatgraph.graph.schema import SCHEMA_STATEMENTS

ResultType = TypeVar("ResultType")
WORKSPACE_ID = UUID("10000000-0000-4000-8000-000000000001")
ENTITY_ID = UUID("10000000-0000-4000-8000-000000000002")
TARGET_ID = UUID("10000000-0000-4000-8000-000000000003")
EVIDENCE_ID = UUID("10000000-0000-4000-8000-000000000004")
RELATIONSHIP_ID = UUID("10000000-0000-4000-8000-000000000005")
NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)


class FakeResult:
    def __init__(self, record: dict[str, Any] | None = None) -> None:
        self.record = record
        self.consumed = False

    async def single(self) -> dict[str, Any] | None:
        return self.record

    async def consume(self) -> None:
        self.consumed = True


class FakeTransaction:
    def __init__(self, records: list[dict[str, Any] | None]) -> None:
        self.records = records
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def run(self, query: str, **parameters: Any) -> FakeResult:
        self.calls.append((query, parameters))
        return FakeResult(self.records.pop(0))


class FakeSession:
    def __init__(self, records: list[dict[str, Any] | None]) -> None:
        self.transaction = FakeTransaction(records)
        self.schema_calls: list[str] = []
        self.schema_results: list[FakeResult] = []

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> None:
        return None

    async def run(self, query: str) -> FakeResult:
        self.schema_calls.append(query)
        result = FakeResult()
        self.schema_results.append(result)
        return result

    async def execute_write(
        self,
        work: Callable[..., Awaitable[ResultType]],
        *args: object,
    ) -> ResultType:
        return await work(cast(AsyncManagedTransaction, self.transaction), *args)

    async def execute_read(
        self,
        work: Callable[..., Awaitable[ResultType]],
        *args: object,
    ) -> ResultType:
        return await work(cast(AsyncManagedTransaction, self.transaction), *args)


class FakeDriver:
    def __init__(self, records: list[dict[str, Any] | None] | None = None) -> None:
        self.database: str | None = None
        self.session_instance = FakeSession(records or [])

    def session(self, *, database: str) -> FakeSession:
        self.database = database
        return self.session_instance


def entity_request() -> EntityCreate:
    return EntityCreate(
        id=ENTITY_ID,
        workspace_id=WORKSPACE_ID,
        entity_type=EntityType.ASSET,
        key="asset-01",
        name="Endpoint 01",
        properties={"hostname": "endpoint-01"},
    )


def stored_entity() -> dict[str, object]:
    return {
        "id": str(ENTITY_ID),
        "workspace_id": str(WORKSPACE_ID),
        "identity_key": "Asset:asset-01",
        "entity_type": "Asset",
        "key": "asset-01",
        "name": "Endpoint 01",
        "sensitive": False,
        "created_at": Neo4jDateTime.from_native(NOW),
        "updated_at": Neo4jDateTime.from_native(NOW),
        "hostname": "endpoint-01",
    }


def relationship_request() -> RelationshipCreate:
    return RelationshipCreate(
        id=RELATIONSHIP_ID,
        workspace_id=WORKSPACE_ID,
        relationship_type=RelationshipType.OBSERVED_ON,
        source_entity_id=ENTITY_ID,
        target_entity_id=TARGET_ID,
        source="sentinel-flow",
        first_seen=NOW,
        last_seen=NOW,
        confidence=0.9,
        evidence_id=EVIDENCE_ID,
        properties={"rule_id": "sigma-001"},
    )


def stored_relationship() -> dict[str, object]:
    request = relationship_request()
    return {
        "id": str(request.id),
        "workspace_id": str(request.workspace_id),
        "relationship_type": request.relationship_type.value,
        "source_entity_id": str(request.source_entity_id),
        "target_entity_id": str(request.target_entity_id),
        "source": request.source,
        "first_seen": request.first_seen,
        "last_seen": request.last_seen,
        "confidence": request.confidence,
        "evidence_id": str(request.evidence_id),
        "created_at": NOW,
        "updated_at": NOW,
        "rule_id": "sigma-001",
    }


def test_schema_installer_consumes_every_idempotent_statement() -> None:
    driver = FakeDriver()
    repository = Neo4jGraphRepository(cast(AsyncDriver, driver), "threatgraph")

    asyncio.run(repository.ensure_schema())

    assert driver.database == "threatgraph"
    assert driver.session_instance.schema_calls == list(SCHEMA_STATEMENTS)
    assert all(result.consumed for result in driver.session_instance.schema_results)
    assert len(SCHEMA_STATEMENTS) == 30
    assert all("IF NOT EXISTS" in statement for statement in SCHEMA_STATEMENTS)


def test_entity_upsert_uses_workspace_identity_and_returns_custom_properties() -> None:
    driver = FakeDriver([{"entity": stored_entity()}])
    repository = Neo4jGraphRepository(cast(AsyncDriver, driver))

    result = asyncio.run(repository.upsert_entity(entity_request()))

    query, parameters = driver.session_instance.transaction.calls[0]
    assert isinstance(result, GraphEntity)
    assert result.id == ENTITY_ID
    assert result.properties == {"hostname": "endpoint-01"}
    assert "MERGE (entity:Entity" in query
    assert "SET entity:Asset" in query
    assert parameters["workspace_id"] == str(WORKSPACE_ID)
    assert parameters["identity_key"] == "Asset:asset-01"


def test_entity_lookup_is_workspace_scoped_and_can_return_none() -> None:
    found_driver = FakeDriver([{"entity": stored_entity()}])
    repository = Neo4jGraphRepository(cast(AsyncDriver, found_driver))

    found = asyncio.run(repository.get_entity(WORKSPACE_ID, ENTITY_ID))

    query, parameters = found_driver.session_instance.transaction.calls[0]
    assert found is not None
    assert "workspace_id: $workspace_id" in query
    assert parameters == {
        "workspace_id": str(WORKSPACE_ID),
        "entity_id": str(ENTITY_ID),
    }

    missing_driver = FakeDriver([None])
    missing_repository = Neo4jGraphRepository(cast(AsyncDriver, missing_driver))
    assert asyncio.run(missing_repository.get_entity(WORKSPACE_ID, ENTITY_ID)) is None


def test_entity_upsert_rejects_missing_or_invalid_neo4j_results() -> None:
    missing_repository = Neo4jGraphRepository(cast(AsyncDriver, FakeDriver([None])))
    with pytest.raises(GraphIntegrityError, match="upserted entity"):
        asyncio.run(missing_repository.upsert_entity(entity_request()))

    invalid_repository = Neo4jGraphRepository(
        cast(AsyncDriver, FakeDriver([{"entity": "invalid"}]))
    )
    with pytest.raises(GraphIntegrityError, match="invalid graph properties"):
        asyncio.run(invalid_repository.upsert_entity(entity_request()))


def test_relationship_upsert_matches_evidence_in_the_same_workspace() -> None:
    driver = FakeDriver([{"relationship": stored_relationship()}])
    repository = Neo4jGraphRepository(cast(AsyncDriver, driver))

    result = asyncio.run(repository.upsert_relationship(relationship_request()))

    query, parameters = driver.session_instance.transaction.calls[0]
    assert isinstance(result, GraphRelationship)
    assert result.properties == {"rule_id": "sigma-001"}
    assert "MATCH (evidence:Entity:Evidence" in query
    assert "[relationship:OBSERVED_ON" in query
    assert parameters["workspace_id"] == str(WORKSPACE_ID)
    assert parameters["evidence_id"] == str(EVIDENCE_ID)


def test_relationship_upsert_requires_endpoints_and_evidence() -> None:
    repository = Neo4jGraphRepository(cast(AsyncDriver, FakeDriver([None])))

    with pytest.raises(GraphIntegrityError, match="same workspace"):
        asyncio.run(repository.upsert_relationship(relationship_request()))
