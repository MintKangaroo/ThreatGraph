from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from threatgraph.graph.models import (
    EntityCreate,
    EntityType,
    RelationshipCreate,
    RelationshipType,
)

WORKSPACE_ID = UUID("00000000-0000-4000-8000-000000000001")
SOURCE_ENTITY_ID = UUID("00000000-0000-4000-8000-000000000002")
TARGET_ENTITY_ID = UUID("00000000-0000-4000-8000-000000000003")
EVIDENCE_ID = UUID("00000000-0000-4000-8000-000000000004")
OBSERVED_AT = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)


def relationship_data() -> dict[str, object]:
    return {
        "workspace_id": WORKSPACE_ID,
        "relationship_type": RelationshipType.OBSERVED_ON,
        "source_entity_id": SOURCE_ENTITY_ID,
        "target_entity_id": TARGET_ENTITY_ID,
        "source": " sentinel-flow ",
        "first_seen": OBSERVED_AT,
        "last_seen": OBSERVED_AT + timedelta(minutes=1),
        "confidence": 0.85,
        "evidence_id": EVIDENCE_ID,
        "properties": {"sensor": "edr-01"},
    }


def test_schema_exposes_all_requested_entity_and_relationship_types() -> None:
    assert {entity.value for entity in EntityType} == {
        "Asset",
        "Identity",
        "Process",
        "File",
        "Domain",
        "IPAddress",
        "URL",
        "Hash",
        "Vulnerability",
        "Alert",
        "Incident",
        "ThreatActor",
        "Malware",
        "Campaign",
        "AttackTechnique",
        "DataSource",
        "Evidence",
    }
    assert {relationship.value for relationship in RelationshipType} == {
        "communicates_with",
        "resolves_to",
        "downloaded",
        "executed",
        "observed_on",
        "authenticated_to",
        "exploited",
        "related_to",
        "attributed_to",
        "uses_technique",
        "affected_by",
        "mitigated_by",
        "part_of_incident",
    }


def test_entity_builds_a_type_scoped_identity_key() -> None:
    entity = EntityCreate(
        workspace_id=WORKSPACE_ID,
        entity_type=EntityType.IP_ADDRESS,
        key=" 203.0.113.7 ",
        properties={"version": 4},
    )

    assert entity.key == "203.0.113.7"
    assert entity.identity_key == "IPAddress:203.0.113.7"


@pytest.mark.parametrize("key", ["", "   "])
def test_entity_rejects_blank_keys(key: str) -> None:
    with pytest.raises(ValidationError):
        EntityCreate(workspace_id=WORKSPACE_ID, entity_type=EntityType.ASSET, key=key)


def test_entity_rejects_reserved_and_unknown_properties() -> None:
    with pytest.raises(ValidationError):
        EntityCreate(
            workspace_id=WORKSPACE_ID,
            entity_type=EntityType.ASSET,
            key="asset-01",
            properties={"workspace_id": "another-workspace"},
        )

    with pytest.raises(ValidationError):
        EntityCreate.model_validate(
            {
                "workspace_id": WORKSPACE_ID,
                "entity_type": EntityType.ASSET,
                "key": "asset-01",
                "unexpected": True,
            }
        )


def test_relationship_requires_evidence_source_time_and_confidence() -> None:
    relationship = RelationshipCreate.model_validate(relationship_data())

    assert relationship.source == "sentinel-flow"
    assert relationship.evidence_id == EVIDENCE_ID
    assert relationship.properties == {"sensor": "edr-01"}


def test_relationship_rejects_invalid_temporal_and_reserved_data() -> None:
    reversed_time = relationship_data()
    reversed_time["last_seen"] = OBSERVED_AT - timedelta(seconds=1)
    with pytest.raises(ValidationError):
        RelationshipCreate.model_validate(reversed_time)

    reserved = relationship_data()
    reserved["properties"] = {"evidence_id": str(EVIDENCE_ID)}
    with pytest.raises(ValidationError):
        RelationshipCreate.model_validate(reserved)


@pytest.mark.parametrize(
    ("field", "value"),
    [("source", "  "), ("confidence", -0.1), ("confidence", 1.1)],
)
def test_relationship_rejects_invalid_required_values(field: str, value: object) -> None:
    data = relationship_data()
    data[field] = value

    with pytest.raises(ValidationError):
        RelationshipCreate.model_validate(data)


def test_relationship_rejects_naive_observation_times() -> None:
    data = relationship_data()
    data["first_seen"] = datetime(2026, 7, 22, 12, 0)

    with pytest.raises(ValidationError):
        RelationshipCreate.model_validate(data)
