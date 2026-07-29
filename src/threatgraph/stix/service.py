"""STIX 2.1 bundle ingestion into the typed ThreatGraph repository."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from stix2 import Bundle, parse

from threatgraph.graph.repository import GraphWriteRepository
from threatgraph.stix.mapper import (
    UnsupportedSTIXObject,
    evidence_for_relationship,
    object_to_entity,
    object_to_relationship,
    stix_id,
)
from threatgraph.stix.store import InMemorySTIXObjectStore, STIXObjectStore
from threatgraph.stix.taxii import STIXBundlePayload, TAXIIBundleSource


class STIXImportError(ValueError):
    """Raised when a payload is not a valid STIX 2.1 bundle."""


@dataclass(frozen=True, slots=True)
class SkippedSTIXObject:
    """A valid STIX object that has no safe graph representation yet."""

    object_id: str
    object_type: str
    reason: str


@dataclass(frozen=True, slots=True)
class IngestReport:
    """Deterministic import result suitable for audit logs and job results."""

    bundle_id: str
    object_count: int
    entity_count: int
    relationship_count: int
    skipped: tuple[SkippedSTIXObject, ...]


class STIXBundleImporter:
    """Validate, preserve, and map STIX bundles into a workspace graph."""

    def __init__(
        self,
        repository: GraphWriteRepository,
        store: STIXObjectStore | None = None,
        max_objects: int = 10_000,
    ) -> None:
        if max_objects < 1:  # pragma: no cover - configuration validation
            raise ValueError("max_objects must be positive")
        self._repository = repository
        self._store = store or InMemorySTIXObjectStore()
        self._max_objects = max_objects

    async def ingest_bundle(
        self,
        workspace_id: UUID,
        payload: STIXBundlePayload,
    ) -> IngestReport:
        bundle = parse_bundle(payload)
        objects = tuple(bundle.objects)
        if len(objects) > self._max_objects:
            raise STIXImportError("STIX bundle exceeds the configured object limit")

        skipped: list[SkippedSTIXObject] = []
        entity_ids: dict[str, UUID] = {}
        entity_types: dict[str, Any] = {}
        entity_count = 0
        for obj in objects:
            try:
                entity = object_to_entity(workspace_id, obj)
            except UnsupportedSTIXObject as error:  # pragma: no cover - parser validates IDs
                skipped.append(_skipped(obj, str(error)))
                continue
            if entity is None:
                if getattr(obj, "type", "") not in {"relationship", "sighting"}:
                    skipped.append(_skipped(obj, "STIX object type or pattern is unsupported"))
                continue
            persisted = await self._repository.upsert_entity(entity)
            object_id = stix_id(obj)
            entity_ids[object_id] = persisted.id
            entity_types[object_id] = entity.entity_type
            entity_count += 1

        relationship_count = 0
        for obj in objects:
            try:
                relationship = object_to_relationship(workspace_id, obj, entity_ids, entity_types)
            except UnsupportedSTIXObject as error:  # pragma: no cover - parser validates IDs
                skipped.append(_skipped(obj, str(error)))
                continue
            if relationship is None:
                if getattr(obj, "type", "") in {"relationship", "sighting"}:
                    skipped.append(
                        _skipped(obj, "relationship references unsupported or missing objects")
                    )
                continue
            await self._repository.upsert_entity(evidence_for_relationship(workspace_id, obj))
            await self._repository.upsert_relationship(relationship)
            relationship_count += 1

        await self._store.save(workspace_id, objects)
        return IngestReport(
            bundle_id=str(getattr(bundle, "id", "")),
            object_count=len(objects),
            entity_count=entity_count,
            relationship_count=relationship_count,
            skipped=tuple(skipped),
        )

    async def ingest_source(
        self,
        workspace_id: UUID,
        source: TAXIIBundleSource,
    ) -> tuple[IngestReport, ...]:
        reports: list[IngestReport] = []
        async for payload in source.iter_bundles():
            reports.append(await self.ingest_bundle(workspace_id, payload))
        return tuple(reports)


def parse_bundle(payload: STIXBundlePayload) -> Bundle:
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    if isinstance(payload, Mapping):
        payload = json.dumps(dict(payload))
    try:
        parsed = parse(payload, allow_custom=True, version="2.1")
    except Exception as error:
        raise STIXImportError("payload is not a valid STIX 2.1 bundle") from error
    if not isinstance(parsed, Bundle) or getattr(parsed, "type", None) != "bundle":
        raise STIXImportError("payload must be a STIX bundle")  # pragma: no cover
    return parsed


def _skipped(obj: Any, reason: str) -> SkippedSTIXObject:
    return SkippedSTIXObject(
        object_id=str(getattr(obj, "id", "unknown")),
        object_type=str(getattr(obj, "type", "unknown")),
        reason=reason,
    )
