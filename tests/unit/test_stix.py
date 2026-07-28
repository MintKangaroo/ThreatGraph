import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from stix2 import AttackPattern, Bundle, Indicator, Relationship, ThreatActor

from threatgraph.graph.models import (
    EntityCreate,
    EntityType,
    GraphEntity,
    GraphRelationship,
    RelationshipCreate,
    RelationshipType,
)
from threatgraph.stix.mapper import (
    UnsupportedSTIXObject,
    _confidence,
    _indicator_type_and_value,
    _times,
    evidence_for_relationship,
    graph_id,
    object_to_entity,
)
from threatgraph.stix.service import STIXBundleImporter, STIXImportError, parse_bundle
from threatgraph.stix.store import InMemorySTIXObjectStore, STIXBundleExporter


class MemoryGraph:
    def __init__(self) -> None:
        self.entities: dict[UUID, GraphEntity] = {}
        self.relationships: dict[UUID, GraphRelationship] = {}

    async def upsert_entity(self, entity: EntityCreate) -> GraphEntity:
        now = datetime.now(UTC)
        value = GraphEntity.model_validate(
            entity.model_dump() | {"created_at": now, "updated_at": now}
        )
        self.entities[value.id] = value
        return value

    async def upsert_relationship(self, relationship: RelationshipCreate) -> GraphRelationship:
        now = datetime.now(UTC)
        value = GraphRelationship.model_validate(
            relationship.model_dump() | {"created_at": now, "updated_at": now}
        )
        self.relationships[value.id] = value
        return value


def make_bundle() -> Bundle:
    actor = ThreatActor(name="demo actor")
    technique = AttackPattern(name="Spearphishing Link")
    indicator = Indicator(pattern="[domain-name:value = 'example.com']", pattern_type="stix")
    relation = Relationship(
        relationship_type="uses", source_ref=actor.id, target_ref=technique.id, confidence=80
    )
    return Bundle(indicator, actor, technique, relation)


@pytest.mark.parametrize("payload_kind", ["string", "bytes", "mapping"])
def test_parse_bundle_accepts_supported_payloads(payload_kind: str) -> None:
    bundle = make_bundle()
    serialized = bundle.serialize()
    if payload_kind == "bytes":
        payload: Any = serialized.encode()
    elif payload_kind == "mapping":
        import json

        payload = json.loads(serialized)
    else:
        payload = serialized
    parsed = parse_bundle(payload)
    assert parsed.id == bundle.id


@pytest.mark.parametrize("payload", ["not-json", {"type": "indicator"}])
def test_parse_bundle_rejects_invalid_payload(payload: Any) -> None:
    with pytest.raises(STIXImportError):
        parse_bundle(payload)


async def _test_import_maps_entities_relationship_evidence_and_exports() -> None:
    repository = MemoryGraph()
    store = InMemorySTIXObjectStore()
    importer = STIXBundleImporter(repository, store)
    workspace_id = uuid4()

    report = await importer.ingest_bundle(workspace_id, make_bundle().serialize())
    assert report.object_count == 4
    assert report.entity_count == 3
    assert report.relationship_count == 1
    assert not report.skipped
    assert any(entity.entity_type == EntityType.EVIDENCE for entity in repository.entities.values())
    relationship = next(iter(repository.relationships.values()))
    assert relationship.relationship_type == RelationshipType.USES_TECHNIQUE
    assert relationship.evidence_id in repository.entities

    exported = await STIXBundleExporter(store).export_workspace(workspace_id)
    assert len(parse_bundle(exported).objects) == 4
    assert await store.list(uuid4()) == ()


async def _test_import_skips_unsupported_indicator_and_missing_relation() -> None:
    indicator = Indicator(pattern="[email-addr:value = 'a@example.com']", pattern_type="stix")
    relation = Relationship(
        relationship_type="related-to",
        source_ref=indicator.id,
        target_ref="identity--00000000-0000-4000-8000-000000000000",
    )
    repository = MemoryGraph()
    report = await STIXBundleImporter(repository).ingest_bundle(
        uuid4(), Bundle(indicator, relation).serialize()
    )
    assert report.entity_count == 0
    assert report.relationship_count == 0
    assert {item.object_type for item in report.skipped} == {"indicator", "relationship"}


async def _test_import_source_and_object_limit() -> None:
    class Source:
        async def iter_bundles(self) -> Any:
            yield make_bundle().serialize()

    importer = STIXBundleImporter(MemoryGraph(), max_objects=4)
    reports = await importer.ingest_source(uuid4(), Source())
    assert len(reports) == 1
    with pytest.raises(STIXImportError, match="object limit"):
        await STIXBundleImporter(MemoryGraph(), max_objects=1).ingest_bundle(
            uuid4(), make_bundle().serialize()
        )


def test_mapper_helpers_and_store_versioning() -> None:
    assert graph_id("indicator--00000000-0000-4000-8000-000000000000") != graph_id(
        "indicator--00000000-0000-4000-8000-000000000000", "evidence"
    )
    assert _indicator_type_and_value("[ipv4-addr:value = '192.0.2.1']") == (
        EntityType.IP_ADDRESS,
        "192.0.2.1",
    )
    assert _indicator_type_and_value("[file:hashes.'SHA-256' = 'abc']")[0] == EntityType.HASH
    assert _indicator_type_and_value("[email-addr:value = 'a@example.com']") == (None, None)
    assert _confidence(type("Object", (), {"confidence": 200})()) == 1.0
    assert _confidence(type("Object", (), {"confidence": -10})()) == 0.0
    now = datetime.now(UTC)
    assert _times(type("Object", (), {"created": now, "modified": now})())[0] == now
    with pytest.raises(UnsupportedSTIXObject):
        object_to_entity(uuid4(), type("Object", (), {"id": "bad", "type": "identity"})())

    store = InMemorySTIXObjectStore()
    old = Indicator(pattern="[domain-name:value = 'old.example']", pattern_type="stix")
    new = Indicator(
        id=old.id,
        pattern="[domain-name:value = 'new.example']",
        pattern_type="stix",
        modified=datetime.now(UTC),
    )
    workspace_id = uuid4()
    asyncio.run(store.save(workspace_id, [new, old]))
    assert (asyncio.run(store.list(workspace_id))[0]).pattern == new.pattern
    with pytest.raises(ValueError):
        asyncio.run(store.save(workspace_id, [object()]))


def test_evidence_requires_valid_stix_id() -> None:
    with pytest.raises(UnsupportedSTIXObject):
        evidence_for_relationship(uuid4(), type("Object", (), {"id": "invalid"})())


def test_import_maps_entities_relationship_evidence_and_exports() -> None:
    asyncio.run(_test_import_maps_entities_relationship_evidence_and_exports())


def test_import_skips_unsupported_indicator_and_missing_relation() -> None:
    asyncio.run(_test_import_skips_unsupported_indicator_and_missing_relation())


def test_import_source_and_object_limit() -> None:
    asyncio.run(_test_import_source_and_object_limit())
