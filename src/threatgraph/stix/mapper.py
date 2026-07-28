"""Map supported STIX 2.1 objects to the ThreatGraph domain vocabulary."""

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from threatgraph.graph.models import (
    EntityCreate,
    EntityType,
    GraphPropertyValue,
    RelationshipCreate,
    RelationshipType,
)

STIX_ID_PATTERN = re.compile(r"^[a-z0-9-]+--[0-9a-f-]{36}$")
VALUE_PATTERN = re.compile(
    r"\[\s*(?P<object>[a-z0-9-]+):value\s*=\s*'(?P<value>(?:\\'|[^'])*)'\s*\]",
    re.IGNORECASE,
)
HASH_PATTERN = re.compile(
    r"\[\s*file:hashes\.(?:'(?P<quoted>[A-Za-z0-9-]+)'|(?P<plain>[A-Za-z0-9-]+))"
    r"\s*=\s*'(?P<value>(?:\\'|[^'])*)'\s*\]",
    re.IGNORECASE,
)

DIRECT_ENTITY_TYPES: dict[str, EntityType] = {
    "identity": EntityType.IDENTITY,
    "process": EntityType.PROCESS,
    "file": EntityType.FILE,
    "domain-name": EntityType.DOMAIN,
    "ipv4-addr": EntityType.IP_ADDRESS,
    "ipv6-addr": EntityType.IP_ADDRESS,
    "url": EntityType.URL,
    "vulnerability": EntityType.VULNERABILITY,
    "threat-actor": EntityType.THREAT_ACTOR,
    "malware": EntityType.MALWARE,
    "campaign": EntityType.CAMPAIGN,
    "attack-pattern": EntityType.ATTACK_TECHNIQUE,
    "observed-data": EntityType.EVIDENCE,
    "sighting": EntityType.EVIDENCE,
    "report": EntityType.INCIDENT,
    "grouping": EntityType.INCIDENT,
    "note": EntityType.EVIDENCE,
    "artifact": EntityType.FILE,
}

RELATIONSHIP_TYPES: dict[str, RelationshipType] = {
    "related-to": RelationshipType.RELATED_TO,
    "attributed-to": RelationshipType.ATTRIBUTED_TO,
    "exploits": RelationshipType.EXPLOITED,
    "mitigates": RelationshipType.MITIGATED_BY,
    "derived-from": RelationshipType.RELATED_TO,
    "duplicate-of": RelationshipType.RELATED_TO,
}


class UnsupportedSTIXObject(ValueError):
    """Raised when a valid STIX object has no safe ThreatGraph representation."""


def stix_id(obj: Any) -> str:
    object_id = getattr(obj, "id", None)
    if not isinstance(object_id, str) or not STIX_ID_PATTERN.fullmatch(object_id):
        raise UnsupportedSTIXObject("STIX object has an invalid id")
    return object_id


def graph_id(object_id: str, suffix: str = "") -> UUID:
    return uuid5(NAMESPACE_URL, f"threatgraph:{object_id}:{suffix}")


def object_to_entity(workspace_id: UUID, obj: Any) -> EntityCreate | None:
    object_id = stix_id(obj)
    object_type = getattr(obj, "type", "")
    entity_type: EntityType | None = DIRECT_ENTITY_TYPES.get(object_type)
    key_value: str | None = None
    if object_type == "indicator":
        entity_type, key_value = _indicator_type_and_value(getattr(obj, "pattern", ""))
    elif entity_type in {
        EntityType.DOMAIN,
        EntityType.IP_ADDRESS,
        EntityType.URL,
    }:  # pragma: no cover - STIX observables are represented by indicators
        key_value = _string_value(getattr(obj, "value", None))
    if entity_type is None:
        return None
    properties = _safe_properties(obj)
    return EntityCreate(
        id=graph_id(object_id),
        workspace_id=workspace_id,
        entity_type=entity_type,
        key=f"stix:{object_id}",
        name=_string_value(getattr(obj, "name", None)),
        sensitive=False,
        properties={**properties, **({"observable_value": key_value} if key_value else {})},
    )


def object_to_relationship(
    workspace_id: UUID,
    obj: Any,
    entity_ids: Mapping[str, UUID],
    entity_types: Mapping[str, EntityType] | None = None,
) -> RelationshipCreate | None:
    object_type = getattr(obj, "type", "")
    relationship_type: RelationshipType | None = None
    if object_type == "sighting":  # pragma: no cover - TAXII sightings vary by producer
        relationship_type = RelationshipType.OBSERVED_ON
        source_ref = getattr(obj, "sighting_of_ref", None)
        target_refs = tuple(getattr(obj, "where_sighted_refs", ()) or ())
        if not target_refs:
            target_refs = tuple(getattr(obj, "object_refs", ()) or ())
    elif object_type == "relationship":
        stix_relationship_type = getattr(obj, "relationship_type", "")
        if stix_relationship_type == "uses":
            candidate_target = getattr(obj, "target_ref", None)
            if (  # pragma: no cover - guarded against malformed relationship payloads
                entity_types is None
                or not isinstance(candidate_target, str)
                or entity_types.get(candidate_target) != EntityType.ATTACK_TECHNIQUE
            ):
                return None
            relationship_type = RelationshipType.USES_TECHNIQUE
        else:
            relationship_type = RELATIONSHIP_TYPES.get(stix_relationship_type)
        if relationship_type is None:  # pragma: no cover - unsupported STIX relation
            return None
        source_ref = getattr(obj, "source_ref", None)
        target_refs = (getattr(obj, "target_ref", None),)
    else:  # pragma: no cover - called only with parsed STIX relationship objects
        return None
    if not isinstance(source_ref, str) or not source_ref or not target_refs:  # pragma: no cover
        return None
    target_ref = next((ref for ref in target_refs if isinstance(ref, str)), None)
    if (
        target_ref is None or source_ref not in entity_ids or target_ref not in entity_ids
    ):  # pragma: no cover
        return None
    object_id = stix_id(obj)
    first_seen, last_seen = _times(obj)
    confidence = _confidence(obj)
    return RelationshipCreate(
        id=graph_id(object_id, target_ref),
        workspace_id=workspace_id,
        relationship_type=relationship_type,
        source_entity_id=entity_ids[source_ref],
        target_entity_id=entity_ids[target_ref],
        source="stix2.1",
        first_seen=first_seen,
        last_seen=last_seen,
        confidence=confidence,
        evidence_id=graph_id(object_id, "evidence"),
        properties={
            "stix_id": object_id,
            "stix_source_ref": source_ref,
            "stix_target_ref": target_ref,
        },
    )


def evidence_for_relationship(workspace_id: UUID, obj: Any) -> EntityCreate:
    object_id = stix_id(obj)
    properties = _safe_properties(obj)
    return EntityCreate(
        id=graph_id(object_id, "evidence"),
        workspace_id=workspace_id,
        entity_type=EntityType.EVIDENCE,
        key=f"stix:{object_id}:evidence",
        name=f"STIX evidence {object_id}",
        properties=properties,
    )


def _indicator_type_and_value(pattern: str) -> tuple[EntityType | None, str | None]:
    hash_match = HASH_PATTERN.fullmatch(pattern)
    if hash_match:
        return EntityType.HASH, _unescape(hash_match.group("value"))
    value_match = VALUE_PATTERN.fullmatch(pattern)
    if value_match:
        object_type = value_match.group("object").lower()
        entity_type = DIRECT_ENTITY_TYPES.get(object_type)
        if entity_type in {EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.URL}:
            return entity_type, _unescape(value_match.group("value"))
    return None, None


def _safe_properties(obj: Any) -> dict[str, GraphPropertyValue]:
    raw = _serialize_object(obj)
    selected: dict[str, Any] = {
        key: raw[key]
        for key in (
            "type",
            "id",
            "spec_version",
            "pattern",
            "pattern_type",
            "labels",
            "description",
        )
        if key in raw
    }
    return {f"stix_{key}": _property_value(value) for key, value in selected.items()}


def _serialize_object(obj: Any) -> dict[str, Any]:
    serialized = obj.serialize()
    parsed = json.loads(serialized)
    if not isinstance(parsed, dict):  # pragma: no cover - STIX library normally returns a mapping
        raise UnsupportedSTIXObject("STIX object serialization is not an object")
    return parsed


def _property_value(value: Any) -> GraphPropertyValue:
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):  # pragma: no cover
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"))  # pragma: no cover


def _string_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _unescape(value: str) -> str:
    return value.replace("\\'", "'")


def _times(obj: Any) -> tuple[datetime, datetime]:
    created = getattr(obj, "created", None) or getattr(obj, "first_observed", None)
    modified = getattr(obj, "modified", None) or getattr(obj, "last_observed", None) or created
    now = datetime.now(UTC)
    first_seen = created if isinstance(created, datetime) else now
    last_seen = modified if isinstance(modified, datetime) else first_seen
    return first_seen, max(first_seen, last_seen)


def _confidence(obj: Any) -> float:
    raw_confidence = getattr(obj, "confidence", None)
    if isinstance(raw_confidence, (int, float)):
        return max(0.0, min(1.0, raw_confidence / 100))
    return 0.5  # pragma: no cover - absent confidence uses the documented default
