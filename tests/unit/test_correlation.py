from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from threatgraph.correlation import (
    CorrelationKind,
    FindingSeverity,
    GraphCorrelator,
)
from threatgraph.graph.models import (
    EntityType,
    GraphEntity,
    GraphRelationship,
    RelationshipType,
)

WORKSPACE_ID = UUID("40000000-0000-4000-8000-000000000001")
OTHER_WORKSPACE_ID = UUID("40000000-0000-4000-8000-000000000099")
NOW = datetime(2026, 7, 29, 2, 0, tzinfo=UTC)


def entity(index: int, entity_type: EntityType, name: str) -> GraphEntity:
    return GraphEntity(
        id=UUID(f"40000000-0000-4000-8000-{index:012d}"),
        workspace_id=WORKSPACE_ID,
        entity_type=entity_type,
        key=name.lower(),
        name=name,
        created_at=NOW,
        updated_at=NOW,
    )


def relationship(
    index: int,
    source: GraphEntity,
    target: GraphEntity,
    relationship_type: RelationshipType = RelationshipType.RELATED_TO,
    confidence: float = 0.95,
    observed_at: datetime = NOW,
    workspace_id: UUID = WORKSPACE_ID,
) -> GraphRelationship:
    return GraphRelationship(
        id=UUID(f"50000000-0000-4000-8000-{index:012d}"),
        workspace_id=workspace_id,
        relationship_type=relationship_type,
        source_entity_id=source.id,
        target_entity_id=target.id,
        source="test-sensor",
        first_seen=observed_at,
        last_seen=observed_at,
        confidence=confidence,
        evidence_id=UUID(f"60000000-0000-4000-8000-{index:012d}"),
        created_at=NOW,
        updated_at=NOW,
    )


def test_correlates_shared_indicator_and_attack_chain_deterministically() -> None:
    incident = entity(2, EntityType.INCIDENT, "INC-42")
    second_incident = entity(3, EntityType.INCIDENT, "INC-43")
    asset = entity(4, EntityType.ASSET, "FIN-WS-07")
    domain = entity(5, EntityType.DOMAIN, "cdn.example")
    address = entity(6, EntityType.IP_ADDRESS, "203.0.113.7")
    technique_one = entity(7, EntityType.ATTACK_TECHNIQUE, "T1003")
    technique_two = entity(8, EntityType.ATTACK_TECHNIQUE, "T1059")
    actor = entity(9, EntityType.THREAT_ACTOR, "Actor")
    nodes = [
        incident,
        second_incident,
        asset,
        domain,
        address,
        technique_one,
        technique_two,
        actor,
        GraphEntity(
            **(
                entity(10, EntityType.ASSET, "Other").model_dump()
                | {"workspace_id": OTHER_WORKSPACE_ID}
            )
        ),
    ]
    active = [
        relationship(1, address, asset),
        relationship(2, address, incident),
        relationship(3, address, domain),
        relationship(
            4,
            incident,
            technique_one,
            RelationshipType.USES_TECHNIQUE,
            confidence=0.8,
        ),
        relationship(
            5,
            incident,
            technique_two,
            RelationshipType.USES_TECHNIQUE,
            confidence=0.8,
        ),
        relationship(
            6,
            second_incident,
            technique_one,
            RelationshipType.USES_TECHNIQUE,
        ),
        relationship(7, actor, incident),
    ]
    ignored = [
        relationship(
            8,
            address,
            asset,
            observed_at=NOW - timedelta(days=2),
        ),
        relationship(9, address, asset, workspace_id=OTHER_WORKSPACE_ID),
        GraphRelationship(
            **(
                relationship(10, address, asset).model_dump()
                | {"target_entity_id": UUID("40000000-0000-4000-8000-000000000098")}
            )
        ),
        relationship(
            11,
            address,
            asset,
            observed_at=NOW + timedelta(hours=1),
        ),
    ]

    correlator = GraphCorrelator()
    report = correlator.correlate(
        WORKSPACE_ID,
        nodes,
        [*active, *ignored],
        window=timedelta(hours=24),
        as_of=NOW,
    )
    repeated = correlator.correlate(
        WORKSPACE_ID,
        nodes,
        [*active, *ignored],
        window=timedelta(hours=24),
        as_of=NOW,
    )

    assert report.scanned_entities == 8
    assert report.scanned_relationships == 7
    assert [finding.kind for finding in report.findings] == [
        CorrelationKind.SHARED_INDICATOR,
        CorrelationKind.TECHNIQUE_CHAIN,
    ]
    shared, chain = report.findings
    assert shared.severity == FindingSeverity.CRITICAL
    assert shared.title == "Shared IPAddress: 203.0.113.7"
    assert len(shared.entity_ids) == 4
    assert len(shared.evidence_ids) == 3
    assert chain.severity == FindingSeverity.HIGH
    assert chain.title == "ATT&CK chain: INC-42"
    assert len(chain.entity_ids) == 3
    assert [finding.id for finding in report.findings] == [
        finding.id for finding in repeated.findings
    ]


def test_correlates_shared_asset_context_at_medium_severity() -> None:
    asset = entity(20, EntityType.ASSET, "APP-01")
    identity = entity(21, EntityType.IDENTITY, "svc-app")
    file = entity(22, EntityType.FILE, "agent.bin")
    unnamed_asset = GraphEntity(
        **(asset.model_dump() | {"id": UUID("40000000-0000-4000-8000-000000000023"), "name": None})
    )
    relationships = [
        relationship(20, unnamed_asset, identity, confidence=0.6),
        relationship(21, unnamed_asset, file, confidence=0.6),
    ]

    report = GraphCorrelator().correlate(
        WORKSPACE_ID,
        [unnamed_asset, identity, file],
        relationships,
        as_of=NOW,
    )

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.kind == CorrelationKind.SHARED_CONTEXT
    assert finding.severity == FindingSeverity.MEDIUM
    assert finding.title == "Shared Asset: app-01"


def test_correlation_bounds_and_empty_graph() -> None:
    with pytest.raises(ValueError, match="maximum"):
        GraphCorrelator(max_window=timedelta(0))

    correlator = GraphCorrelator(max_window=timedelta(days=2))
    for invalid_window in (timedelta(0), timedelta(days=3)):
        with pytest.raises(ValueError, match="outside"):
            correlator.correlate(
                WORKSPACE_ID,
                [],
                [],
                window=invalid_window,
                as_of=NOW,
            )
    with pytest.raises(ValueError, match="timezone"):
        correlator.correlate(
            WORKSPACE_ID,
            [],
            [],
            as_of=datetime(2026, 7, 29),
        )

    report = correlator.correlate(WORKSPACE_ID, [], [], as_of=NOW)
    assert report.findings == ()
    assert report.window_end == NOW
    assert report.window_start == NOW - timedelta(hours=24)
