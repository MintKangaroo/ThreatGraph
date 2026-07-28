"""Deterministic IOC normalization and privacy-aware deduplication."""

import ipaddress
import re
from enum import StrEnum
from urllib.parse import SplitResult, urlsplit, urlunsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field

from threatgraph.graph.models import EntityCreate, EntityType, GraphPropertyValue

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 96: "sha384", 128: "sha512"}
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")


class IOCNormalizationError(ValueError):
    """Raised when an IOC cannot be safely canonicalized."""


class IOCSource(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH = "hash"


class NormalizedIOC(BaseModel):
    """Canonical IOC value and its stable workspace identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_type: EntityType
    source_type: IOCSource
    canonical_value: str = Field(min_length=1)
    identity_key: str = Field(min_length=1)
    display_value: str = Field(min_length=1)
    sensitive: bool = False

    @property
    def graph_id(self) -> UUID:
        return uuid5(NAMESPACE_URL, f"threatgraph:ioc:{self.identity_key}")

    def to_entity(self, workspace_id: UUID) -> EntityCreate:
        properties: dict[str, GraphPropertyValue] = {
            "ioc_type": self.source_type.value,
            "canonical_value": self.display_value if self.sensitive else self.canonical_value,
            "masked": self.sensitive,
        }
        return EntityCreate(
            id=self.graph_id,
            workspace_id=workspace_id,
            entity_type=self.entity_type,
            key=self.identity_key,
            name=self.display_value,
            sensitive=self.sensitive,
            properties=properties,
        )


class IOCNormalizer:
    """Normalize a stream of IOC values and remove canonical duplicates."""

    def __init__(self, *, mask_sensitive: bool = False) -> None:
        self._mask_sensitive = mask_sensitive

    def normalize(
        self,
        entity_type: EntityType,
        value: str,
        *,
        sensitive: bool = False,
    ) -> NormalizedIOC:
        return normalize_ioc(
            entity_type,
            value,
            sensitive=sensitive,
            mask_sensitive=self._mask_sensitive,
        )

    def deduplicate(self, values: list[NormalizedIOC]) -> tuple[NormalizedIOC, ...]:
        unique: dict[str, NormalizedIOC] = {}
        for value in values:
            unique.setdefault(value.identity_key, value)
        return tuple(unique.values())


def normalize_ioc(
    entity_type: EntityType,
    value: str,
    *,
    sensitive: bool = False,
    mask_sensitive: bool = False,
) -> NormalizedIOC:
    """Return one canonical IOC or raise for an unsupported graph type/value."""

    raw = value.strip()
    if not raw:
        raise IOCNormalizationError("IOC value must not be blank")
    if entity_type == EntityType.DOMAIN:
        canonical = _domain(raw)
        source_type = IOCSource.DOMAIN
    elif entity_type == EntityType.IP_ADDRESS:
        canonical = _ip(raw)
        source_type = IOCSource.IP
    elif entity_type == EntityType.URL:
        canonical = _url(raw)
        source_type = IOCSource.URL
    elif entity_type == EntityType.HASH:
        canonical = _hash(raw)
        source_type = IOCSource.HASH
    else:
        raise IOCNormalizationError(f"unsupported IOC entity type: {entity_type}")
    identity_key = f"{source_type.value}:{canonical}"
    should_mask = sensitive and mask_sensitive
    return NormalizedIOC(
        entity_type=entity_type,
        source_type=source_type,
        canonical_value=canonical,
        identity_key=identity_key,
        display_value=_mask(canonical, source_type) if should_mask else canonical,
        sensitive=should_mask,
    )


def _domain(value: str) -> str:
    candidate = value.rstrip(".").lower()
    try:
        result = candidate.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise IOCNormalizationError("invalid domain name") from error
    if not result or "." not in result or any(not part for part in result.split(".")):
        raise IOCNormalizationError("invalid domain name")
    return result


def _ip(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as error:
        raise IOCNormalizationError("invalid IP address") from error


def _url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise IOCNormalizationError("URL must have an HTTP(S) scheme and host")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise IOCNormalizationError("invalid URL host or port") from error
    netloc = host
    if parsed.username or parsed.password:
        raise IOCNormalizationError("URL credentials are not supported")
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    if port is not None and not default_port:
        netloc = f"{netloc}:{port}"
    normalized = SplitResult(parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    return urlunsplit(normalized)


def _hash(value: str) -> str:
    candidate = value.lower()
    if len(candidate) not in HASH_LENGTHS or not HEX_PATTERN.fullmatch(candidate):
        raise IOCNormalizationError("hash must be a supported hexadecimal digest")
    return candidate


def _mask(value: str, source_type: IOCSource) -> str:
    if source_type == IOCSource.IP:
        address = ipaddress.ip_address(value)
        if address.version == 4:
            return ".".join(value.split(".")[:2] + ["x", "x"])
        return ":".join(value.split(":")[:3] + ["*"])
    if source_type == IOCSource.HASH:
        return f"{value[:6]}…{value[-4:]}"
    parsed = urlsplit(value) if source_type == IOCSource.URL else None
    if parsed is not None:
        return urlunsplit(parsed._replace(netloc="***"))
    labels = value.split(".")
    return "***." + ".".join(labels[-2:]) if len(labels) > 1 else "***"
