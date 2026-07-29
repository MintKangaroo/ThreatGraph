from datetime import UTC, datetime
from uuid import UUID

from threatgraph.correlation import (
    CorrelationFinding,
    CorrelationKind,
    FindingSeverity,
)
from threatgraph.graph.models import (
    EntityType,
    GraphEntity,
    GraphRelationship,
    RelationshipType,
)
from threatgraph.narrative import build_grounded_narrative

WORKSPACE_ID = UUID("70000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
SOURCE_ID = UUID("70000000-0000-4000-8000-000000000002")
TARGET_ID = UUID("70000000-0000-4000-8000-000000000003")
RELATIONSHIP_ID = UUID("70000000-0000-4000-8000-000000000004")
MISSING_RELATIONSHIP_ID = UUID("70000000-0000-4000-8000-000000000005")
EVIDENCE_ID = UUID("70000000-0000-4000-8000-000000000006")


def graph_entity(
    entity_id: UUID,
    entity_type: EntityType,
    key: str,
    name: str | None,
    workspace_id: UUID = WORKSPACE_ID,
) -> GraphEntity:
    return GraphEntity(
        id=entity_id,
        workspace_id=workspace_id,
        entity_type=entity_type,
        key=key,
        name=name,
        created_at=NOW,
        updated_at=NOW,
    )


def graph_relationship() -> GraphRelationship:
    return GraphRelationship(
        id=RELATIONSHIP_ID,
        workspace_id=WORKSPACE_ID,
        relationship_type=RelationshipType.COMMUNICATES_WITH,
        source_entity_id=SOURCE_ID,
        target_entity_id=TARGET_ID,
        source="network-sensor",
        first_seen=NOW,
        last_seen=NOW,
        confidence=0.92,
        evidence_id=EVIDENCE_ID,
        created_at=NOW,
        updated_at=NOW,
    )


def finding(
    *,
    kind: CorrelationKind = CorrelationKind.SHARED_INDICATOR,
    confidence: float = 0.92,
    relationship_ids: tuple[UUID, ...] = (RELATIONSHIP_ID,),
) -> CorrelationFinding:
    return CorrelationFinding(
        id=UUID("70000000-0000-4000-8000-000000000007"),
        workspace_id=WORKSPACE_ID,
        kind=kind,
        severity=FindingSeverity.HIGH,
        title="Shared IPAddress",
        summary="An address connects two entities.",
        entity_ids=(SOURCE_ID, TARGET_ID),
        relationship_ids=relationship_ids,
        evidence_ids=(EVIDENCE_ID,),
        first_seen=NOW,
        last_seen=NOW,
        confidence=confidence,
    )


def test_builds_claims_that_directly_reference_evidence() -> None:
    nodes = [
        graph_entity(SOURCE_ID, EntityType.ASSET, "asset-01", "Endpoint 01"),
        graph_entity(TARGET_ID, EntityType.IP_ADDRESS, "203.0.113.7", None),
    ]

    narrative = build_grounded_narrative(
        finding(),
        nodes,
        [graph_relationship()],
    )

    assert narrative.grounded is True
    assert narrative.gaps == ()
    assert narrative.claims[0].text == ("Endpoint 01 communicates with 203.0.113.7.")
    assert narrative.claims[0].evidence_id == EVIDENCE_ID
    assert "1 claim(s)" in narrative.summary
    assert "1 Evidence record(s)" in narrative.summary


def test_reports_missing_facts_and_low_confidence_without_fabrication() -> None:
    wrong_workspace = UUID("70000000-0000-4000-8000-000000000099")
    nodes = [
        graph_entity(SOURCE_ID, EntityType.INCIDENT, "incident-01", "INC-01"),
        graph_entity(
            TARGET_ID,
            EntityType.ATTACK_TECHNIQUE,
            "attack:T1003",
            "T1003",
            workspace_id=wrong_workspace,
        ),
    ]

    narrative = build_grounded_narrative(
        finding(
            kind=CorrelationKind.TECHNIQUE_CHAIN,
            confidence=0.5,
            relationship_ids=(RELATIONSHIP_ID, MISSING_RELATIONSHIP_ID),
        ),
        nodes,
        [graph_relationship()],
    )

    assert narrative.grounded is False
    assert narrative.claims == ()
    assert narrative.gaps == (
        f"Relationship {RELATIONSHIP_ID} has an unavailable endpoint.",
        f"Relationship {MISSING_RELATIONSHIP_ID} is unavailable.",
        "Overall confidence is below the analyst review threshold.",
        "Fewer than two ATT&CK techniques are available for the chain.",
    )
    assert narrative.summary.endswith("No relationship claims can be verified.")
