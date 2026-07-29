from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest

from threatgraph.attack import (
    attack_external_id,
    attack_graph_id,
    attack_pattern_to_entity,
    normalize_attack_id,
    sigma_attack_ids,
    sigma_technique_entities,
    sigma_technique_relationships,
)
from threatgraph.graph.models import EntityType, RelationshipType

WORKSPACE_ID = UUID("30000000-0000-4000-8000-000000000001")
SOURCE_ID = UUID("30000000-0000-4000-8000-000000000002")
EVIDENCE_ID = UUID("30000000-0000-4000-8000-000000000003")
OBSERVED_AT = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)


def technique_object() -> SimpleNamespace:
    return SimpleNamespace(
        external_references=[
            {"source_name": "other", "external_id": "X-1"},
            {"source_name": "mitre-attack", "external_id": "t1003.001"},
        ],
        name="LSASS Memory",
        description="Credential material from LSASS memory.",
        kill_chain_phases=[
            {"phase_name": "credential-access"},
            SimpleNamespace(phase_name="credential-access"),
            SimpleNamespace(phase_name="defense-evasion"),
        ],
        x_mitre_platforms=["Windows", "Windows", ""],
        revoked=False,
        x_mitre_deprecated=True,
    )


def test_attack_identity_and_stix_mapping_are_stable() -> None:
    assert normalize_attack_id(" t1003.001 ") == "T1003.001"
    assert attack_graph_id("T1003.001") == attack_graph_id("t1003.001")
    with pytest.raises(ValueError, match="invalid MITRE"):
        normalize_attack_id("TA0001")

    obj = technique_object()
    assert attack_external_id(obj) == "T1003.001"
    entity = attack_pattern_to_entity(WORKSPACE_ID, obj)

    assert entity is not None
    assert entity.id == attack_graph_id("T1003.001")
    assert entity.entity_type == EntityType.ATTACK_TECHNIQUE
    assert entity.key == "attack:T1003.001"
    assert entity.name == "LSASS Memory"
    assert entity.properties == {
        "attack_id": "T1003.001",
        "tactics": ["credential-access", "defense-evasion"],
        "platforms": ["Windows"],
        "revoked": False,
        "deprecated": True,
        "description": "Credential material from LSASS memory.",
    }


def test_attack_mapping_handles_object_references_and_unknown_patterns() -> None:
    object_reference = SimpleNamespace(
        source_name="mitre-attack",
        external_id="T1566",
    )
    assert attack_external_id(SimpleNamespace(external_references=[object_reference])) == "T1566"
    unknown = SimpleNamespace(
        external_references=[{"source_name": "mitre-attack", "external_id": "invalid"}]
    )
    assert attack_external_id(unknown) is None
    assert attack_pattern_to_entity(WORKSPACE_ID, unknown) is None

    minimal = SimpleNamespace(
        external_references=[{"source_name": "mitre-attack", "external_id": "T1059"}],
        name=None,
        description=None,
        kill_chain_phases=[],
        x_mitre_platforms=[],
    )
    entity = attack_pattern_to_entity(WORKSPACE_ID, minimal)
    assert entity is not None
    assert entity.name == "T1059"
    assert "description" not in entity.properties


def test_sigma_tags_create_entities_and_grounded_relationships() -> None:
    tags = ["attack.t1003", "ATTACK.T1003.001", "attack.t1003", "product.windows"]

    assert sigma_attack_ids(tags) == ("T1003", "T1003.001")
    entities = sigma_technique_entities(WORKSPACE_ID, tags)
    assert [entity.key for entity in entities] == [
        "attack:T1003",
        "attack:T1003.001",
    ]
    assert all(entity.entity_type == EntityType.ATTACK_TECHNIQUE for entity in entities)

    relationships = sigma_technique_relationships(
        WORKSPACE_ID,
        " sigma-rule-01 ",
        SOURCE_ID,
        EVIDENCE_ID,
        OBSERVED_AT,
        tags,
        confidence=0.9,
    )
    assert len(relationships) == 2
    assert all(
        relationship.relationship_type == RelationshipType.USES_TECHNIQUE
        for relationship in relationships
    )
    assert relationships[0].source == "sigma:sigma-rule-01"
    assert relationships[0].evidence_id == EVIDENCE_ID
    assert relationships[0].first_seen == OBSERVED_AT
    assert (
        relationships[0].id
        == sigma_technique_relationships(
            WORKSPACE_ID,
            "sigma-rule-01",
            SOURCE_ID,
            EVIDENCE_ID,
            OBSERVED_AT,
            tags,
            confidence=0.9,
        )[0].id
    )

    with pytest.raises(ValueError, match="rule id"):
        sigma_technique_relationships(
            WORKSPACE_ID,
            " ",
            SOURCE_ID,
            EVIDENCE_ID,
            OBSERVED_AT,
            tags,
        )
