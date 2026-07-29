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
    GraphPage,
    GraphPath,
    GraphRelationship,
    RelationshipCreate,
)
from threatgraph.graph.schema import SCHEMA_STATEMENTS


class GraphIntegrityError(RuntimeError):
    """Raised when a requested graph mutation would violate domain integrity."""


class GraphWriteRepository(Protocol):
    """Minimal mutation boundary used by ingestion pipelines."""

    async def upsert_entity(self, entity: EntityCreate) -> GraphEntity:
        """Create or update an entity by its workspace-local identity key."""

    async def upsert_relationship(
        self,
        relationship: RelationshipCreate,
    ) -> GraphRelationship:
        """Create or update a relationship backed by Evidence in the same workspace."""


class GraphRepository(GraphWriteRepository, Protocol):
    """Full storage boundary for workspace-scoped threat graphs."""

    async def ensure_schema(self) -> None:
        """Install idempotent graph constraints and indexes."""

    async def get_entity(self, workspace_id: UUID, entity_id: UUID) -> GraphEntity | None:
        """Return an entity only when it belongs to the requested workspace."""


class GraphQueryRepository(Protocol):
    """Read boundary for bounded, workspace-scoped graph exploration."""

    async def get_subgraph(
        self,
        workspace_id: UUID,
        limit: int,
        offset: int,
    ) -> GraphPage:
        """Return a bounded page of entities and relationships from one workspace."""

    async def get_entity(
        self,
        workspace_id: UUID,
        entity_id: UUID,
    ) -> GraphEntity | None:
        """Return a workspace entity used as an exploration anchor."""

    async def get_subgraph_in_range(
        self,
        workspace_id: UUID,
        since: datetime,
        until: datetime,
        limit: int,
        offset: int,
    ) -> GraphPage:
        """Return entities connected by relationships observed in a time range."""

    async def get_neighborhood(
        self,
        workspace_id: UUID,
        entity_id: UUID,
        depth: int,
        limit: int,
        since: datetime | None,
    ) -> GraphPage:
        """Expand a bounded neighborhood around one workspace entity."""

    async def get_shortest_path(
        self,
        workspace_id: UUID,
        source_entity_id: UUID,
        target_entity_id: UUID,
        max_depth: int,
        since: datetime | None,
    ) -> GraphPath | None:
        """Return a bounded shortest path inside one workspace."""


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

    async def get_subgraph(
        self,
        workspace_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> GraphPage:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if offset < 0:
            raise ValueError("offset must not be negative")
        async with self._driver.session(database=self._database) as session:
            return await session.execute_read(
                self._get_subgraph,
                workspace_id,
                limit,
                offset,
            )

    async def get_subgraph_in_range(
        self,
        workspace_id: UUID,
        since: datetime,
        until: datetime,
        limit: int = 100,
        offset: int = 0,
    ) -> GraphPage:
        _validate_pagination(limit, offset)
        _validate_time_range(since, until)
        async with self._driver.session(database=self._database) as session:
            return await session.execute_read(
                self._get_subgraph_in_range,
                workspace_id,
                since,
                until,
                limit,
                offset,
            )

    async def get_neighborhood(
        self,
        workspace_id: UUID,
        entity_id: UUID,
        depth: int = 1,
        limit: int = 100,
        since: datetime | None = None,
    ) -> GraphPage:
        if not 1 <= depth <= 5:
            raise ValueError("depth must be between 1 and 5")
        _validate_pagination(limit, 0)
        _validate_optional_time(since)
        async with self._driver.session(database=self._database) as session:
            return await session.execute_read(
                self._get_neighborhood,
                workspace_id,
                entity_id,
                depth,
                limit,
                since,
            )

    async def get_shortest_path(
        self,
        workspace_id: UUID,
        source_entity_id: UUID,
        target_entity_id: UUID,
        max_depth: int = 8,
        since: datetime | None = None,
    ) -> GraphPath | None:
        if not 1 <= max_depth <= 8:
            raise ValueError("max_depth must be between 1 and 8")
        _validate_optional_time(since)
        async with self._driver.session(database=self._database) as session:
            return await session.execute_read(
                self._get_shortest_path,
                workspace_id,
                source_entity_id,
                target_entity_id,
                max_depth,
                since,
            )

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
    async def _get_subgraph(
        transaction: AsyncManagedTransaction,
        workspace_id: UUID,
        limit: int,
        offset: int,
    ) -> GraphPage:
        result = await transaction.run(
            """
            MATCH (entity:Entity {workspace_id: $workspace_id})
            WITH entity
            ORDER BY entity.updated_at DESC, entity.id ASC
            WITH collect(entity) AS all_entities
            WITH
                all_entities[$offset..$page_end] AS page_nodes,
                size(all_entities) AS total_nodes
            UNWIND CASE
                WHEN size(page_nodes) = 0 THEN [null]
                ELSE page_nodes
            END AS source
            OPTIONAL MATCH (source)-[relationship]->(target:Entity {
                workspace_id: $workspace_id
            })
            WHERE
                relationship.workspace_id = $workspace_id
                AND target IN page_nodes
            RETURN
                [node IN page_nodes | properties(node)] AS nodes,
                [
                    item IN collect(DISTINCT relationship)
                    WHERE item IS NOT NULL | properties(item)
                ] AS relationships,
                total_nodes
            """,
            workspace_id=str(workspace_id),
            limit=limit,
            offset=offset,
            page_end=offset + limit,
        )
        record = await result.single()
        if record is None:
            raise GraphIntegrityError("Neo4j did not return a subgraph result")
        raw_nodes = record.get("nodes")
        raw_relationships = record.get("relationships")
        total_nodes = record.get("total_nodes")
        if (
            not isinstance(raw_nodes, list)
            or not isinstance(raw_relationships, list)
            or not isinstance(total_nodes, int)
        ):
            raise GraphIntegrityError("Neo4j returned an invalid subgraph result")
        return GraphPage(
            nodes=[_deserialize_entity(node) for node in raw_nodes],
            relationships=[
                _deserialize_relationship(relationship) for relationship in raw_relationships
            ],
            total_nodes=total_nodes,
            limit=limit,
            offset=offset,
        )

    @staticmethod
    async def _get_subgraph_in_range(
        transaction: AsyncManagedTransaction,
        workspace_id: UUID,
        since: datetime,
        until: datetime,
        limit: int,
        offset: int,
    ) -> GraphPage:
        result = await transaction.run(
            """
            OPTIONAL MATCH (source:Entity {
                workspace_id: $workspace_id
            })-[relationship]-(target:Entity {
                workspace_id: $workspace_id
            })
            WHERE
                relationship.workspace_id = $workspace_id
                AND relationship.last_seen >= $since
                AND relationship.first_seen <= $until
            WITH
                collect(DISTINCT source) + collect(DISTINCT target) AS duplicate_nodes,
                collect(DISTINCT relationship) AS all_relationships
            WITH
                reduce(
                    unique_nodes = [],
                    node IN duplicate_nodes |
                    CASE
                        WHEN node IS NULL OR node IN unique_nodes THEN unique_nodes
                        ELSE unique_nodes + node
                    END
                ) AS all_nodes,
                all_relationships
            WITH
                all_nodes[$offset..$page_end] AS page_nodes,
                all_relationships,
                size(all_nodes) AS total_nodes
            WITH
                page_nodes,
                total_nodes,
                [node IN page_nodes | node.id] AS page_node_ids,
                all_relationships
            RETURN
                [node IN page_nodes | properties(node)] AS nodes,
                [
                    item IN all_relationships
                    WHERE
                        item.source_entity_id IN page_node_ids
                        AND item.target_entity_id IN page_node_ids
                    | properties(item)
                ] AS relationships,
                total_nodes
            """,
            workspace_id=str(workspace_id),
            since=since,
            until=until,
            offset=offset,
            page_end=offset + limit,
        )
        return _deserialize_page(result=await result.single(), limit=limit, offset=offset)

    @staticmethod
    async def _get_neighborhood(
        transaction: AsyncManagedTransaction,
        workspace_id: UUID,
        entity_id: UUID,
        depth: int,
        limit: int,
        since: datetime | None,
    ) -> GraphPage:
        query = f"""
        MATCH (center:Entity {{
            workspace_id: $workspace_id,
            id: $entity_id
        }})
        OPTIONAL MATCH path=(center)-[*1..{depth}]-(neighbor:Entity {{
            workspace_id: $workspace_id
        }})
        WHERE
            path IS NULL
            OR (
                all(node IN nodes(path) WHERE node.workspace_id = $workspace_id)
                AND all(
                    item IN relationships(path)
                    WHERE
                        item.workspace_id = $workspace_id
                        AND ($since IS NULL OR item.last_seen >= $since)
                )
            )
        WITH
            center,
            [
                node IN collect(DISTINCT neighbor)
                WHERE node IS NOT NULL
            ][..$neighbor_limit] AS neighbors
        WITH [center] + neighbors AS page_nodes
        UNWIND page_nodes AS source
        OPTIONAL MATCH (source)-[relationship]-(target:Entity {{
            workspace_id: $workspace_id
        }})
        WHERE
            target IN page_nodes
            AND relationship.workspace_id = $workspace_id
            AND ($since IS NULL OR relationship.last_seen >= $since)
        RETURN
            [node IN page_nodes | properties(node)] AS nodes,
            [
                item IN collect(DISTINCT relationship)
                WHERE item IS NOT NULL | properties(item)
            ] AS relationships,
            size(page_nodes) AS total_nodes
        """
        result = await transaction.run(
            query,
            workspace_id=str(workspace_id),
            entity_id=str(entity_id),
            neighbor_limit=limit - 1,
            since=since,
        )
        record = await result.single()
        if record is None:
            return GraphPage(
                nodes=[],
                relationships=[],
                total_nodes=0,
                limit=limit,
                offset=0,
            )
        return _deserialize_page(result=record, limit=limit, offset=0)

    @staticmethod
    async def _get_shortest_path(
        transaction: AsyncManagedTransaction,
        workspace_id: UUID,
        source_entity_id: UUID,
        target_entity_id: UUID,
        max_depth: int,
        since: datetime | None,
    ) -> GraphPath | None:
        query = f"""
        MATCH (source:Entity {{
            workspace_id: $workspace_id,
            id: $source_entity_id
        }})
        MATCH (target:Entity {{
            workspace_id: $workspace_id,
            id: $target_entity_id
        }})
        OPTIONAL MATCH path=shortestPath((source)-[*..{max_depth}]-(target))
        WHERE
            path IS NULL
            OR (
                all(node IN nodes(path) WHERE node.workspace_id = $workspace_id)
                AND all(
                    item IN relationships(path)
                    WHERE
                        item.workspace_id = $workspace_id
                        AND ($since IS NULL OR item.last_seen >= $since)
                )
            )
        RETURN
            CASE
                WHEN path IS NULL THEN []
                ELSE [node IN nodes(path) | properties(node)]
            END AS nodes,
            CASE
                WHEN path IS NULL THEN []
                ELSE [item IN relationships(path) | properties(item)]
            END AS relationships
        """
        result = await transaction.run(
            query,
            workspace_id=str(workspace_id),
            source_entity_id=str(source_entity_id),
            target_entity_id=str(target_entity_id),
            since=since,
        )
        record = await result.single()
        if record is None:
            return None
        raw_nodes = record.get("nodes")
        raw_relationships = record.get("relationships")
        if not isinstance(raw_nodes, list) or not isinstance(raw_relationships, list):
            raise GraphIntegrityError("Neo4j returned an invalid graph path")
        if not raw_nodes:
            return None
        return GraphPath(
            nodes=tuple(_deserialize_entity(node) for node in raw_nodes),
            relationships=tuple(
                _deserialize_relationship(relationship) for relationship in raw_relationships
            ),
        )

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


def _validate_pagination(limit: int, offset: int) -> None:
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    if offset < 0:
        raise ValueError("offset must not be negative")


def _validate_optional_time(value: datetime | None) -> None:
    if value is not None and value.tzinfo is None:
        raise ValueError("time filters must be timezone-aware")


def _validate_time_range(since: datetime, until: datetime) -> None:
    _validate_optional_time(since)
    _validate_optional_time(until)
    if since > until:
        raise ValueError("since must not be after until")


def _deserialize_page(
    result: Mapping[str, Any] | None,
    limit: int,
    offset: int,
) -> GraphPage:
    if result is None:
        raise GraphIntegrityError("Neo4j did not return a graph page")
    raw_nodes = result.get("nodes")
    raw_relationships = result.get("relationships")
    total_nodes = result.get("total_nodes")
    if (
        not isinstance(raw_nodes, list)
        or not isinstance(raw_relationships, list)
        or not isinstance(total_nodes, int)
    ):
        raise GraphIntegrityError("Neo4j returned an invalid graph page")
    return GraphPage(
        nodes=[_deserialize_entity(node) for node in raw_nodes],
        relationships=[
            _deserialize_relationship(relationship) for relationship in raw_relationships
        ],
        total_nodes=total_nodes,
        limit=limit,
        offset=offset,
    )
