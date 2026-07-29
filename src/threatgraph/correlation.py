"""Deterministic, Evidence-backed graph correlation rules."""

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from statistics import fmean
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field

from threatgraph.graph.models import (
    EntityType,
    GraphEntity,
    GraphModel,
    GraphRelationship,
    RelationshipType,
)

CORRELATION_PIVOT_TYPES = frozenset(
    {
        EntityType.IP_ADDRESS,
        EntityType.DOMAIN,
        EntityType.URL,
        EntityType.HASH,
        EntityType.FILE,
        EntityType.ASSET,
        EntityType.IDENTITY,
    }
)


class CorrelationKind(StrEnum):
    """Supported explainable correlation rule families."""

    SHARED_INDICATOR = "shared_indicator"
    SHARED_CONTEXT = "shared_context"
    TECHNIQUE_CHAIN = "technique_chain"


class FindingSeverity(StrEnum):
    """Normalized finding severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


class CorrelationFinding(GraphModel):
    """One deterministic finding grounded in graph relationships."""

    id: UUID
    workspace_id: UUID
    kind: CorrelationKind
    severity: FindingSeverity
    title: str = Field(min_length=1, max_length=256)
    summary: str = Field(min_length=1, max_length=2048)
    entity_ids: tuple[UUID, ...] = Field(min_length=2)
    relationship_ids: tuple[UUID, ...] = Field(min_length=1)
    evidence_ids: tuple[UUID, ...] = Field(min_length=1)
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    confidence: float = Field(ge=0, le=1)


class CorrelationReport(GraphModel):
    """Result of a bounded time-window correlation run."""

    workspace_id: UUID
    window_start: AwareDatetime
    window_end: AwareDatetime
    scanned_entities: int = Field(ge=0)
    scanned_relationships: int = Field(ge=0)
    findings: tuple[CorrelationFinding, ...]


class GraphCorrelator:
    """Correlate shared pivots and ATT&CK chains without inventing facts."""

    def __init__(self, max_window: timedelta = timedelta(days=30)) -> None:
        if max_window <= timedelta(0):
            raise ValueError("maximum correlation window must be positive")
        self._max_window = max_window

    def correlate(
        self,
        workspace_id: UUID,
        nodes: list[GraphEntity],
        relationships: list[GraphRelationship],
        window: timedelta = timedelta(hours=24),
        as_of: datetime | None = None,
    ) -> CorrelationReport:
        """Run bounded correlation rules over one workspace graph page."""

        if window <= timedelta(0) or window > self._max_window:
            raise ValueError("correlation window is outside the allowed range")
        window_end = as_of or datetime.now(UTC)
        if window_end.tzinfo is None:
            raise ValueError("correlation end time must be timezone-aware")
        window_start = window_end - window
        node_map = {node.id: node for node in nodes if node.workspace_id == workspace_id}
        active = [
            relationship
            for relationship in relationships
            if relationship.workspace_id == workspace_id
            and relationship.source_entity_id in node_map
            and relationship.target_entity_id in node_map
            and relationship.last_seen >= window_start
            and relationship.first_seen <= window_end
        ]
        findings = [
            *self._shared_pivot_findings(workspace_id, node_map, active),
            *self._technique_chain_findings(workspace_id, node_map, active),
        ]
        severity_order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
        }
        findings.sort(
            key=lambda finding: (
                severity_order[finding.severity],
                -finding.last_seen.timestamp(),
                str(finding.id),
            )
        )
        return CorrelationReport(
            workspace_id=workspace_id,
            window_start=window_start,
            window_end=window_end,
            scanned_entities=len(node_map),
            scanned_relationships=len(active),
            findings=tuple(findings),
        )

    @staticmethod
    def _shared_pivot_findings(
        workspace_id: UUID,
        nodes: dict[UUID, GraphEntity],
        relationships: list[GraphRelationship],
    ) -> list[CorrelationFinding]:
        by_entity: dict[UUID, list[GraphRelationship]] = defaultdict(list)
        for relationship in relationships:
            by_entity[relationship.source_entity_id].append(relationship)
            by_entity[relationship.target_entity_id].append(relationship)

        findings: list[CorrelationFinding] = []
        for pivot_id, pivot_relationships in by_entity.items():
            pivot = nodes[pivot_id]
            if pivot.entity_type not in CORRELATION_PIVOT_TYPES:
                continue
            neighbor_ids = {
                relationship.target_entity_id
                if relationship.source_entity_id == pivot_id
                else relationship.source_entity_id
                for relationship in pivot_relationships
            }
            if len(neighbor_ids) < 2:
                continue
            kind = (
                CorrelationKind.SHARED_CONTEXT
                if pivot.entity_type in {EntityType.ASSET, EntityType.IDENTITY}
                else CorrelationKind.SHARED_INDICATOR
            )
            ordered_relationships = sorted(
                pivot_relationships,
                key=lambda relationship: str(relationship.id),
            )
            ordered_entities = (pivot_id, *sorted(neighbor_ids, key=str))
            confidence = fmean(relationship.confidence for relationship in ordered_relationships)
            pivot_name = pivot.name or pivot.key
            findings.append(
                CorrelationFinding(
                    id=_finding_id(
                        workspace_id,
                        kind,
                        pivot_id,
                        [relationship.id for relationship in ordered_relationships],
                    ),
                    workspace_id=workspace_id,
                    kind=kind,
                    severity=_severity(confidence, len(ordered_entities)),
                    title=f"Shared {pivot.entity_type.value}: {pivot_name}",
                    summary=(
                        f"{pivot_name} connects {len(neighbor_ids)} entities through "
                        f"{len(ordered_relationships)} observed relationships."
                    ),
                    entity_ids=ordered_entities,
                    relationship_ids=tuple(
                        relationship.id for relationship in ordered_relationships
                    ),
                    evidence_ids=_evidence_ids(ordered_relationships),
                    first_seen=min(
                        relationship.first_seen for relationship in ordered_relationships
                    ),
                    last_seen=max(relationship.last_seen for relationship in ordered_relationships),
                    confidence=confidence,
                )
            )
        return findings

    @staticmethod
    def _technique_chain_findings(
        workspace_id: UUID,
        nodes: dict[UUID, GraphEntity],
        relationships: list[GraphRelationship],
    ) -> list[CorrelationFinding]:
        findings: list[CorrelationFinding] = []
        for incident in nodes.values():
            if incident.entity_type != EntityType.INCIDENT:
                continue
            technique_relationships = [
                relationship
                for relationship in relationships
                if relationship.relationship_type == RelationshipType.USES_TECHNIQUE
                and incident.id
                in {
                    relationship.source_entity_id,
                    relationship.target_entity_id,
                }
                and nodes[
                    relationship.target_entity_id
                    if relationship.source_entity_id == incident.id
                    else relationship.source_entity_id
                ].entity_type
                == EntityType.ATTACK_TECHNIQUE
            ]
            if len(technique_relationships) < 2:
                continue
            ordered_relationships = sorted(
                technique_relationships,
                key=lambda relationship: str(relationship.id),
            )
            technique_ids = {
                relationship.target_entity_id
                if relationship.source_entity_id == incident.id
                else relationship.source_entity_id
                for relationship in ordered_relationships
            }
            confidence = fmean(relationship.confidence for relationship in ordered_relationships)
            incident_name = incident.name or incident.key
            findings.append(
                CorrelationFinding(
                    id=_finding_id(
                        workspace_id,
                        CorrelationKind.TECHNIQUE_CHAIN,
                        incident.id,
                        [relationship.id for relationship in ordered_relationships],
                    ),
                    workspace_id=workspace_id,
                    kind=CorrelationKind.TECHNIQUE_CHAIN,
                    severity=_severity(confidence, len(technique_ids) + 1),
                    title=f"ATT&CK chain: {incident_name}",
                    summary=(
                        f"{incident_name} is grounded in {len(technique_ids)} ATT&CK "
                        "techniques observed in the selected time window."
                    ),
                    entity_ids=(
                        incident.id,
                        *sorted(technique_ids, key=str),
                    ),
                    relationship_ids=tuple(
                        relationship.id for relationship in ordered_relationships
                    ),
                    evidence_ids=_evidence_ids(ordered_relationships),
                    first_seen=min(
                        relationship.first_seen for relationship in ordered_relationships
                    ),
                    last_seen=max(relationship.last_seen for relationship in ordered_relationships),
                    confidence=confidence,
                )
            )
        return findings


def _severity(confidence: float, entity_count: int) -> FindingSeverity:
    if confidence >= 0.9 and entity_count >= 4:
        return FindingSeverity.CRITICAL
    if confidence >= 0.75:
        return FindingSeverity.HIGH
    return FindingSeverity.MEDIUM


def _evidence_ids(
    relationships: list[GraphRelationship],
) -> tuple[UUID, ...]:
    return tuple(sorted({relationship.evidence_id for relationship in relationships}, key=str))


def _finding_id(
    workspace_id: UUID,
    kind: CorrelationKind,
    pivot_id: UUID,
    relationship_ids: list[UUID],
) -> UUID:
    material = ":".join(sorted(str(identifier) for identifier in relationship_ids))
    return uuid5(
        NAMESPACE_URL,
        f"threatgraph:correlation:{workspace_id}:{kind.value}:{pivot_id}:{material}",
    )
