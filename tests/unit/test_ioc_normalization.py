from uuid import uuid4

import pytest

from threatgraph.graph.models import EntityType
from threatgraph.ioc import IOCNormalizationError, IOCNormalizer, normalize_ioc


def test_normalizes_and_deduplicates_supported_iocs() -> None:
    domain = normalize_ioc(EntityType.DOMAIN, " ExAmPle.COM. ")
    assert domain.canonical_value == "example.com"
    assert domain.identity_key == "domain:example.com"
    assert domain.to_entity(uuid4()).key == domain.identity_key

    assert normalize_ioc(EntityType.IP_ADDRESS, "2001:0db8::1").canonical_value == "2001:db8::1"
    assert (
        normalize_ioc(EntityType.URL, "HTTPS://Example.COM:443/a?q=1#fragment").canonical_value
        == "https://example.com/a?q=1"
    )
    assert normalize_ioc(EntityType.HASH, "A" * 64).canonical_value == "a" * 64

    normalizer = IOCNormalizer()
    values = [domain, normalizer.normalize(EntityType.DOMAIN, "example.com")]
    assert normalizer.deduplicate(values) == (domain,)


@pytest.mark.parametrize(
    ("entity_type", "value"),
    [
        (EntityType.DOMAIN, "localhost"),
        (EntityType.IP_ADDRESS, "999.1.1.1"),
        (EntityType.URL, "ftp://example.com"),
        (EntityType.URL, "https://user:pass@example.com"),
        (EntityType.URL, "https://example.com:bad"),
        (EntityType.HASH, "not-a-hash"),
        (EntityType.ASSET, "example.com"),
        (EntityType.DOMAIN, "   "),
    ],
)
def test_rejects_invalid_or_unsupported_iocs(entity_type: EntityType, value: str) -> None:
    with pytest.raises(IOCNormalizationError):
        normalize_ioc(entity_type, value)


def test_masks_sensitive_values_without_changing_identity() -> None:
    masked = normalize_ioc(
        EntityType.DOMAIN,
        "secret.example.com",
        sensitive=True,
        mask_sensitive=True,
    )
    assert masked.sensitive is True
    assert masked.display_value == "***.example.com"
    assert masked.canonical_value == "secret.example.com"
    assert masked.to_entity(uuid4()).properties["canonical_value"] == masked.display_value

    ip = normalize_ioc(EntityType.IP_ADDRESS, "192.0.2.10", sensitive=True, mask_sensitive=True)
    assert ip.display_value == "192.0.x.x"
    digest = normalize_ioc(EntityType.HASH, "a" * 64, sensitive=True, mask_sensitive=True)
    assert digest.display_value == "aaaaaa…aaaa"
    url = normalize_ioc(
        EntityType.URL, "https://example.com/path", sensitive=True, mask_sensitive=True
    )
    assert url.display_value == "https://***/path"

    ipv6 = normalize_ioc(
        EntityType.IP_ADDRESS,
        "2001:db8::1",
        sensitive=True,
        mask_sensitive=True,
    )
    assert ipv6.display_value == "2001:db8::*"


def test_idna_and_non_default_port_are_canonicalized() -> None:
    assert (
        normalize_ioc(EntityType.DOMAIN, "bücher.example").canonical_value
        == "xn--bcher-kva.example"
    )
    assert (
        normalize_ioc(EntityType.URL, "http://example.com:8080").canonical_value
        == "http://example.com:8080/"
    )
    assert (
        normalize_ioc(EntityType.URL, "http://[2001:db8::1]/").canonical_value
        == "http://[2001:db8::1]/"
    )


def test_rejects_invalid_unicode_domain() -> None:
    with pytest.raises(IOCNormalizationError):
        normalize_ioc(EntityType.DOMAIN, "\ud800.example")
