"""Generate deterministic narratives that cite graph Evidence."""

from uuid import UUID

from pydantic import Field

from threatgraph.correlation import CorrelationFinding, CorrelationKind
from threatgraph.graph.models import GraphEntity, GraphModel, GraphRelationship


class GroundedClaim(GraphModel):
    """A single graph-derived statement and its supporting Evidence."""

    text: str = Field(min_length=1, max_length=1024)
    relationship_id: UUID
    evidence_id: UUID
    confidence: float = Field(ge=0, le=1)


class GroundedNarrative(GraphModel):
    """An explanation that separates supported claims from evidence gaps."""

    finding_id: UUID
    title: str = Field(min_length=1, max_length=256)
    summary: str = Field(min_length=1, max_length=2048)
    claims: tuple[GroundedClaim, ...]
    gaps: tuple[str, ...]
    grounded: bool


def build_grounded_narrative(
    finding: CorrelationFinding,
    nodes: list[GraphEntity],
    relationships: list[GraphRelationship],
) -> GroundedNarrative:
    """Explain a finding using only supplied workspace graph facts."""

    node_map = {
        node.id: node
        for node in nodes
        if node.workspace_id == finding.workspace_id and node.id in set(finding.entity_ids)
    }
    relationship_map = {
        relationship.id: relationship
        for relationship in relationships
        if relationship.workspace_id == finding.workspace_id
    }
    claims: list[GroundedClaim] = []
    gaps: list[str] = []
    for relationship_id in finding.relationship_ids:
        relationship = relationship_map.get(relationship_id)
        if relationship is None:
            gaps.append(f"Relationship {relationship_id} is unavailable.")
            continue
        source = node_map.get(relationship.source_entity_id)
        target = node_map.get(relationship.target_entity_id)
        if source is None or target is None:
            gaps.append(f"Relationship {relationship_id} has an unavailable endpoint.")
            continue
        claims.append(
            GroundedClaim(
                text=(
                    f"{_label(source)} {relationship.relationship_type.value.replace('_', ' ')} "
                    f"{_label(target)}."
                ),
                relationship_id=relationship.id,
                evidence_id=relationship.evidence_id,
                confidence=relationship.confidence,
            )
        )
    if finding.confidence < 0.6:
        gaps.append("Overall confidence is below the analyst review threshold.")
    if finding.kind == CorrelationKind.TECHNIQUE_CHAIN:
        technique_count = sum(
            node.entity_type.value == "AttackTechnique" for node in node_map.values()
        )
        if technique_count < 2:
            gaps.append("Fewer than two ATT&CK techniques are available for the chain.")
    if claims:
        summary = (
            f"{finding.summary} {len(claims)} claim(s) are directly backed by "
            f"{len({claim.evidence_id for claim in claims})} Evidence record(s)."
        )
    else:
        summary = f"{finding.summary} No relationship claims can be verified."
    return GroundedNarrative(
        finding_id=finding.id,
        title=finding.title,
        summary=summary,
        claims=tuple(claims),
        gaps=tuple(gaps),
        grounded=bool(claims) and not gaps,
    )


def _label(entity: GraphEntity) -> str:
    return entity.name or entity.key
