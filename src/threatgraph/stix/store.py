"""STIX object preservation and bundle export interfaces."""

from collections.abc import Iterable
from typing import Any, Protocol, cast
from uuid import UUID

from stix2 import Bundle

STIXObject = Any


class STIXObjectStore(Protocol):
    """Persistence boundary for lossless workspace-scoped STIX objects."""

    async def save(self, workspace_id: UUID, objects: Iterable[STIXObject]) -> None:
        """Upsert parsed STIX objects for a workspace."""

    async def list(self, workspace_id: UUID) -> tuple[STIXObject, ...]:
        """Return preserved STIX objects for a workspace in stable order."""


class InMemorySTIXObjectStore:
    """Small deterministic store for local development and adapter tests."""

    def __init__(self) -> None:
        self._objects: dict[UUID, dict[str, STIXObject]] = {}

    async def save(self, workspace_id: UUID, objects: Iterable[STIXObject]) -> None:
        workspace_objects = self._objects.setdefault(workspace_id, {})
        for obj in objects:
            object_id = _object_id(obj)
            existing = workspace_objects.get(object_id)
            if existing is None or _modified(obj) >= _modified(existing):
                workspace_objects[object_id] = obj

    async def list(self, workspace_id: UUID) -> tuple[STIXObject, ...]:
        objects = self._objects.get(workspace_id, {})
        return tuple(objects[object_id] for object_id in sorted(objects))


class STIXBundleExporter:
    """Export preserved workspace objects as a STIX 2.1 bundle."""

    def __init__(self, store: STIXObjectStore) -> None:
        self._store = store

    async def export_workspace(self, workspace_id: UUID) -> bytes:
        objects = await self._store.list(workspace_id)
        serialized = cast(str, Bundle(*objects).serialize())
        return serialized.encode("utf-8")


def _object_id(obj: STIXObject) -> str:
    object_id = getattr(obj, "id", None)
    if not isinstance(object_id, str) or not object_id:
        raise ValueError("STIX objects must have an id")
    return object_id


def _modified(obj: STIXObject) -> str:
    modified = getattr(obj, "modified", None)
    return modified.isoformat() if modified is not None else ""
