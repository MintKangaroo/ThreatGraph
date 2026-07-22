"""Workspace-safe Neo4j repository for threat intelligence graphs."""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from neo4j import AsyncDriver, AsyncManagedTransaction
from neo4j.time import DateTime as Neo4jDateTime

from threatgraph.graph.models import (
    ENTITY_RESERVED_PROPERTIES,
    RELATIONSHIP_RESERVED_PROPERTIES,
    EntityCreate,
    GraphEntity,
    GraphRelationship,
    RelationshipCreate,
)
from threatgraph.graph.schema import SCHEMA_STATEMENTS


class GraphIntegrityError(RuntimeError):
    """Raised when a requested graph mutation would violate domain integrity."""


class GraphRepository(Protocol):
    """Storage boundary for workspace-scoped threat graphs."""

    async def ensure_schema(self) -> None:
        """Install idempotent graph constraints and indexes."""

    async def upsert_entity(self, entity: EntityCreate) -> GraphEntity:
        """Create or update an entity by its workspace-local identity key."""

    async def get_entity(self, workspace_id: UUID, entity_id: UUID) -> GraphEntity | None:
        """Return an entity only when it belongs to the requested workspace."""

    async def upsert_relationship(
        self,
        relationship: RelationshipCreate,
    ) -> GraphRelationship:
        """Create or update a relationship backed by Evidence in the same workspace."""


class Neo4jGraphRepository:
    """Neo4j implementation that scopes every query by workspace_id."""

    def __init__(self, driver: AsyncDriver, database: str = "neo4j") -> None:
        self._driver = driver
        self._database = database

    async def ensure_schema(self) -> None:
        async with self._driver.session(database=self._database) as session:
            for statement in SCHEMA_STATEMENTS:
                result = await session.run(statement)
                await result.consume()

    async def upsert_entity(self, entity: EntityCreate) -> GraphEntity:
        timestamp = datetime.now(UTC)
        async with self._driver.session(database=self._database) as session:
            persisted = await session.execute_write(self._upsert_entity, entity, timestamp)
        return persisted

    async def get_entity(self, workspace_id: UUID, entity_id: UUID) -> GraphEntity | None:
        async with self._driver.session(database=self._database) as session:
            persisted = await session.execute_read(self._get_entity, workspace_id, entity_id)
        return persisted

    async def upsert_relationship(
        self,
        relationship: RelationshipCreate,
    ) -> GraphRelationship:
        timestamp = datetime.now(UTC)
        async with self._driver.session(database=self._database) as session:
            persisted = await session.execute_write(
                self._upsert_relationship,
                relationship,
                timestamp,
            )
        return persisted

    @staticmethod
    async def _upsert_entity(
        transaction: AsyncManagedTransaction,
        entity: EntityCreate,
        timestamp: datetime,
    ) -> GraphEntity:
        label = entity.entity_type.value
        query = f"""
        MERGE (entity:Entity {{
            workspace_id: $workspace_id,
            identity_key: $identity_key
        }})
        ON CREATE SET
            entity.id = $entity_id,
            entity.created_at = $timestamp
        SET entity:{label}
        SET
            entity.entity_type = $entity_type,
            entity.key = $key,
            entity.name = $name,
            entity.sensitive = $sensitive,
            entity.updated_at = $timestamp
        SET entity += $properties
        RETURN properties(entity) AS entity
        """
        result = await transaction.run(
            query,
            workspace_id=str(entity.workspace_id),
            identity_key=entity.identity_key,
            entity_id=str(entity.id),
            entity_type=entity.entity_type.value,
            key=entity.key,
            name=entity.name,
            sensitive=entity.sensitive,
            properties=entity.properties,
            timestamp=timestamp,
        )
        record = await result.single()
        if record is None:
            raise GraphIntegrityError("Neo4j did not return the upserted entity")
        return _deserialize_entity(record["entity"])

    @staticmethod
    async def _get_entity(
        transaction: AsyncManagedTransaction,
        workspace_id: UUID,
        entity_id: UUID,
    ) -> GraphEntity | None:
        result = await transaction.run(
            """
            MATCH (entity:Entity {workspace_id: $workspace_id, id: $entity_id})
            RETURN properties(entity) AS entity
            """,
            workspace_id=str(workspace_id),
            entity_id=str(entity_id),
        )
        record = await result.single()
        return None if record is None else _deserialize_entity(record["entity"])

    @staticmethod
    async def _upsert_relationship(
        transaction: AsyncManagedTransaction,
        relationship: RelationshipCreate,
        timestamp: datetime,
    ) -> GraphRelationship:
        relationship_label = relationship.relationship_type.name
        query = f"""
        MATCH (source:Entity {{
            workspace_id: $workspace_id,
            id: $source_entity_id
        }})
        MATCH (target:Entity {{
            workspace_id: $workspace_id,
            id: $target_entity_id
        }})
        MATCH (evidence:Entity:Evidence {{
            workspace_id: $workspace_id,
            id: $evidence_id
        }})
        MERGE (source)-[relationship:{relationship_label} {{
            workspace_id: $workspace_id,
            id: $relationship_id
        }}]->(target)
        ON CREATE SET relationship.created_at = $timestamp
        SET
            relationship.relationship_type = $relationship_type,
            relationship.source_entity_id = $source_entity_id,
            relationship.target_entity_id = $target_entity_id,
            relationship.source = $source,
            relationship.first_seen = $first_seen,
            relationship.last_seen = $last_seen,
            relationship.confidence = $confidence,
            relationship.evidence_id = $evidence_id,
            relationship.updated_at = $timestamp
        SET relationship += $properties
        RETURN properties(relationship) AS relationship
        """
        result = await transaction.run(
            query,
            workspace_id=str(relationship.workspace_id),
            relationship_id=str(relationship.id),
            relationship_type=relationship.relationship_type.value,
            source_entity_id=str(relationship.source_entity_id),
            target_entity_id=str(relationship.target_entity_id),
            source=relationship.source,
            first_seen=relationship.first_seen,
            last_seen=relationship.last_seen,
            confidence=relationship.confidence,
            evidence_id=str(relationship.evidence_id),
            properties=relationship.properties,
            timestamp=timestamp,
        )
        record = await result.single()
        if record is None:
            raise GraphIntegrityError(
                "relationship endpoints and Evidence must exist in the same workspace"
            )
        return _deserialize_relationship(record["relationship"])


def _as_property_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise GraphIntegrityError("Neo4j returned invalid graph properties")
    return dict(value)


def _deserialize_entity(value: Any) -> GraphEntity:
    stored = _as_property_mapping(value)
    properties = {
        key: property_value
        for key, property_value in stored.items()
        if key not in ENTITY_RESERVED_PROPERTIES
    }
    return GraphEntity.model_validate(
        {
            "id": stored.get("id"),
            "workspace_id": stored.get("workspace_id"),
            "entity_type": stored.get("entity_type"),
            "key": stored.get("key"),
            "name": stored.get("name"),
            "sensitive": stored.get("sensitive", False),
            "created_at": _native_datetime(stored.get("created_at")),
            "updated_at": _native_datetime(stored.get("updated_at")),
            "properties": properties,
        }
    )


def _deserialize_relationship(value: Any) -> GraphRelationship:
    stored = _as_property_mapping(value)
    properties = {
        key: property_value
        for key, property_value in stored.items()
        if key not in RELATIONSHIP_RESERVED_PROPERTIES
    }
    return GraphRelationship.model_validate(
        {
            "id": stored.get("id"),
            "workspace_id": stored.get("workspace_id"),
            "relationship_type": stored.get("relationship_type"),
            "source_entity_id": stored.get("source_entity_id"),
            "target_entity_id": stored.get("target_entity_id"),
            "source": stored.get("source"),
            "first_seen": _native_datetime(stored.get("first_seen")),
            "last_seen": _native_datetime(stored.get("last_seen")),
            "confidence": stored.get("confidence"),
            "evidence_id": stored.get("evidence_id"),
            "created_at": _native_datetime(stored.get("created_at")),
            "updated_at": _native_datetime(stored.get("updated_at")),
            "properties": properties,
        }
    )


def _native_datetime(value: Any) -> Any:
    return value.to_native() if isinstance(value, Neo4jDateTime) else value
