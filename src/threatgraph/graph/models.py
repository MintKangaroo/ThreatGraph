"""Typed graph entities, relationships, and shared invariants."""

from enum import StrEnum
from typing import Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

type GraphPropertyValue = (
    str | int | float | bool | list[str] | list[int] | list[float] | list[bool]
)

ENTITY_RESERVED_PROPERTIES = frozenset(
    {
        "id",
        "workspace_id",
        "identity_key",
        "entity_type",
        "key",
        "name",
        "sensitive",
        "created_at",
        "updated_at",
    }
)

RELATIONSHIP_RESERVED_PROPERTIES = frozenset(
    {
        "id",
        "workspace_id",
        "relationship_type",
        "source_entity_id",
        "target_entity_id",
        "source",
        "first_seen",
        "last_seen",
        "confidence",
        "evidence_id",
        "created_at",
        "updated_at",
    }
)


class EntityType(StrEnum):
    """Supported threat intelligence node labels."""

    ASSET = "Asset"
    IDENTITY = "Identity"
    PROCESS = "Process"
    FILE = "File"
    DOMAIN = "Domain"
    IP_ADDRESS = "IPAddress"
    URL = "URL"
    HASH = "Hash"
    VULNERABILITY = "Vulnerability"
    ALERT = "Alert"
    INCIDENT = "Incident"
    THREAT_ACTOR = "ThreatActor"
    MALWARE = "Malware"
    CAMPAIGN = "Campaign"
    ATTACK_TECHNIQUE = "AttackTechnique"
    DATA_SOURCE = "DataSource"
    EVIDENCE = "Evidence"


class RelationshipType(StrEnum):
    """Supported evidence-backed relationship types."""

    COMMUNICATES_WITH = "communicates_with"
    RESOLVES_TO = "resolves_to"
    DOWNLOADED = "downloaded"
    EXECUTED = "executed"
    OBSERVED_ON = "observed_on"
    AUTHENTICATED_TO = "authenticated_to"
    EXPLOITED = "exploited"
    RELATED_TO = "related_to"
    ATTRIBUTED_TO = "attributed_to"
    USES_TECHNIQUE = "uses_technique"
    AFFECTED_BY = "affected_by"
    MITIGATED_BY = "mitigated_by"
    PART_OF_INCIDENT = "part_of_incident"


class GraphModel(BaseModel):
    """Strict base model for data crossing the graph boundary."""

    model_config = ConfigDict(extra="forbid")


class EntityCreate(GraphModel):
    """Workspace-scoped entity upsert request."""

    id: UUID = Field(default_factory=uuid4)
    workspace_id: UUID
    entity_type: EntityType
    key: str = Field(min_length=1, max_length=1024)
    name: str | None = Field(default=None, max_length=1024)
    sensitive: bool = False
    properties: dict[str, GraphPropertyValue] = Field(default_factory=dict)

    @field_validator("key")
    @classmethod
    def key_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("entity key must not be blank")
        return normalized

    @field_validator("properties")
    @classmethod
    def properties_must_not_override_schema(
        cls,
        value: dict[str, GraphPropertyValue],
    ) -> dict[str, GraphPropertyValue]:
        if ENTITY_RESERVED_PROPERTIES.intersection(value):
            raise ValueError("entity properties contain reserved schema fields")
        return value

    @property
    def identity_key(self) -> str:
        """Return the workspace-local idempotency key used by Neo4j MERGE."""

        return f"{self.entity_type.value}:{self.key}"


class GraphEntity(EntityCreate):
    """Persisted entity returned by a graph repository."""

    created_at: AwareDatetime
    updated_at: AwareDatetime


class RelationshipCreate(GraphModel):
    """Evidence-backed, workspace-scoped relationship upsert request."""

    id: UUID = Field(default_factory=uuid4)
    workspace_id: UUID
    relationship_type: RelationshipType
    source_entity_id: UUID
    target_entity_id: UUID
    source: str = Field(min_length=1, max_length=512)
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    confidence: float = Field(ge=0, le=1)
    evidence_id: UUID
    properties: dict[str, GraphPropertyValue] = Field(default_factory=dict)

    @field_validator("source")
    @classmethod
    def source_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("relationship source must not be blank")
        return normalized

    @field_validator("properties")
    @classmethod
    def relationship_properties_must_not_override_schema(
        cls,
        value: dict[str, GraphPropertyValue],
    ) -> dict[str, GraphPropertyValue]:
        if RELATIONSHIP_RESERVED_PROPERTIES.intersection(value):
            raise ValueError("relationship properties contain reserved schema fields")
        return value

    @model_validator(mode="after")
    def last_seen_must_not_precede_first_seen(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be greater than or equal to first_seen")
        return self


class GraphRelationship(RelationshipCreate):
    """Persisted relationship returned by a graph repository."""

    created_at: AwareDatetime
    updated_at: AwareDatetime


class GraphPage(GraphModel):
    """Bounded workspace subgraph returned to query clients."""

    nodes: list[GraphEntity]
    relationships: list[GraphRelationship]
    total_nodes: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)

    @property
    def next_offset(self) -> int | None:
        """Return the next offset while more workspace entities remain."""

        candidate = self.offset + len(self.nodes)
        return candidate if candidate < self.total_nodes else None


class GraphPath(GraphModel):
    """A bounded path between two workspace entities."""

    nodes: tuple[GraphEntity, ...]
    relationships: tuple[GraphRelationship, ...]

    @property
    def length(self) -> int:
        """Return the number of relationships in the path."""

        return len(self.relationships)
