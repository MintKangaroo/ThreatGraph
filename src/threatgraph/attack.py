"""MITRE ATT&CK technique identity and Sigma mapping helpers."""

import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from threatgraph.graph.models import (
    EntityCreate,
    EntityType,
    GraphPropertyValue,
    RelationshipCreate,
    RelationshipType,
)

ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
SIGMA_ATTACK_TAG_PATTERN = re.compile(
    r"^attack\.(?P<technique>t\d{4}(?:\.\d{3})?)$",
    re.IGNORECASE,
)


def normalize_attack_id(value: str) -> str:
    """Return a canonical ATT&CK technique or sub-technique identifier."""

    normalized = value.strip().upper()
    if not ATTACK_ID_PATTERN.fullmatch(normalized):
        raise ValueError("invalid MITRE ATT&CK technique id")
    return normalized


def attack_graph_id(external_id: str) -> UUID:
    """Return the deterministic graph UUID for an ATT&CK technique."""

    return uuid5(NAMESPACE_URL, f"threatgraph:attack:{normalize_attack_id(external_id)}")


def attack_external_id(obj: Any) -> str | None:
    """Extract a canonical MITRE ATT&CK external ID from a STIX object."""

    references = getattr(obj, "external_references", ()) or ()
    for reference in references:
        if isinstance(reference, Mapping):
            source_name = reference.get("source_name")
            external_id = reference.get("external_id")
        else:
            source_name = getattr(reference, "source_name", None)
            external_id = getattr(reference, "external_id", None)
        if (
            source_name == "mitre-attack"
            and isinstance(external_id, str)
            and ATTACK_ID_PATTERN.fullmatch(external_id.strip())
        ):
            return normalize_attack_id(external_id)
    return None


def attack_pattern_to_entity(workspace_id: UUID, obj: Any) -> EntityCreate | None:
    """Convert an ATT&CK STIX attack-pattern into a stable graph entity."""

    external_id = attack_external_id(obj)
    if external_id is None:
        return None
    name = getattr(obj, "name", None)
    description = getattr(obj, "description", None)
    tactics = _tactics(getattr(obj, "kill_chain_phases", ()) or ())
    platforms = _strings(getattr(obj, "x_mitre_platforms", ()) or ())
    properties: dict[str, GraphPropertyValue] = {
        "attack_id": external_id,
        "tactics": tactics,
        "platforms": platforms,
        "revoked": bool(getattr(obj, "revoked", False)),
        "deprecated": bool(getattr(obj, "x_mitre_deprecated", False)),
    }
    if isinstance(description, str) and description:
        properties["description"] = description
    return EntityCreate(
        id=attack_graph_id(external_id),
        workspace_id=workspace_id,
        entity_type=EntityType.ATTACK_TECHNIQUE,
        key=f"attack:{external_id}",
        name=name if isinstance(name, str) and name else external_id,
        properties=properties,
    )


def sigma_attack_ids(tags: Iterable[str]) -> tuple[str, ...]:
    """Extract stable, de-duplicated ATT&CK IDs from Sigma tags."""

    found: set[str] = set()
    for tag in tags:
        match = SIGMA_ATTACK_TAG_PATTERN.fullmatch(tag.strip())
        if match:
            found.add(normalize_attack_id(match.group("technique")))
    return tuple(sorted(found))


def sigma_technique_entities(
    workspace_id: UUID,
    tags: Iterable[str],
) -> tuple[EntityCreate, ...]:
    """Build placeholder technique entities for Sigma mappings."""

    return tuple(
        EntityCreate(
            id=attack_graph_id(external_id),
            workspace_id=workspace_id,
            entity_type=EntityType.ATTACK_TECHNIQUE,
            key=f"attack:{external_id}",
            name=external_id,
            properties={"attack_id": external_id, "mapping_source": "sigma"},
        )
        for external_id in sigma_attack_ids(tags)
    )


def sigma_technique_relationships(
    workspace_id: UUID,
    rule_id: str,
    source_entity_id: UUID,
    evidence_id: UUID,
    observed_at: datetime,
    tags: Iterable[str],
    confidence: float = 0.8,
) -> tuple[RelationshipCreate, ...]:
    """Map Sigma ATT&CK tags to deterministic, Evidence-backed relationships."""

    normalized_rule_id = rule_id.strip()
    if not normalized_rule_id:
        raise ValueError("Sigma rule id must not be blank")
    return tuple(
        RelationshipCreate(
            id=uuid5(
                NAMESPACE_URL,
                f"threatgraph:sigma:{workspace_id}:{normalized_rule_id}:{external_id}",
            ),
            workspace_id=workspace_id,
            relationship_type=RelationshipType.USES_TECHNIQUE,
            source_entity_id=source_entity_id,
            target_entity_id=attack_graph_id(external_id),
            source=f"sigma:{normalized_rule_id}",
            first_seen=observed_at,
            last_seen=observed_at,
            confidence=confidence,
            evidence_id=evidence_id,
            properties={
                "sigma_rule_id": normalized_rule_id,
                "attack_id": external_id,
            },
        )
        for external_id in sigma_attack_ids(tags)
    )


def _tactics(phases: Iterable[Any]) -> list[str]:
    values: set[str] = set()
    for phase in phases:
        value = (
            phase.get("phase_name")
            if isinstance(phase, Mapping)
            else getattr(phase, "phase_name", None)
        )
        if isinstance(value, str) and value:
            values.add(value)
    return sorted(values)


def _strings(values: Iterable[Any]) -> list[str]:
    return sorted({value for value in values if isinstance(value, str) and value})
