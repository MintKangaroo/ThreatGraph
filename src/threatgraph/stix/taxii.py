"""TAXII adapter contract kept independent from the synchronous client library."""

from collections.abc import AsyncIterator, Mapping
from typing import Protocol

STIXBundlePayload = str | bytes | Mapping[str, object]


class TAXIIBundleSource(Protocol):
    """Async source contract implemented by a TAXII 2.1 polling adapter."""

    def iter_bundles(self) -> AsyncIterator[STIXBundlePayload]:
        """Yield STIX bundle payloads without coupling ingestion to HTTP details."""
