from datetime import UTC, datetime
from uuid import UUID

import pytest

from threatgraph.correlation import (
    CorrelationFinding,
    CorrelationKind,
    CorrelationReport,
    FindingSeverity,
)
from threatgraph.narrative import GroundedClaim, GroundedNarrative
from threatgraph.platforms import IntegrationPlatform, build_platform_export


def _report() -> tuple[CorrelationReport, GroundedNarrative, datetime]:
    workspace_id = UUID("a0000000-0000-4000-8000-000000000001")
    finding_id = UUID("a0000000-0000-4000-8000-000000000002")
    relationship_id = UUID("a0000000-0000-4000-8000-000000000003")
    evidence_id = UUID("a0000000-0000-4000-8000-000000000004")
    now = datetime(2026, 7, 29, 5, 0, tzinfo=UTC)
    report = CorrelationReport(
        workspace_id=workspace_id,
        window_start=datetime(2026, 7, 28, 5, 0, tzinfo=UTC),
        window_end=now,
        scanned_entities=3,
        scanned_relationships=1,
        findings=(
            CorrelationFinding(
                id=finding_id,
                workspace_id=workspace_id,
                kind=CorrelationKind.SHARED_INDICATOR,
                severity=FindingSeverity.HIGH,
                title="Shared indicator",
                summary="Two incidents share an indicator.",
                entity_ids=(
                    UUID("a0000000-0000-4000-8000-000000000005"),
                    UUID("a0000000-0000-4000-8000-000000000006"),
                ),
                relationship_ids=(relationship_id,),
                evidence_ids=(evidence_id,),
                first_seen=datetime(2026, 7, 29, 4, 0, tzinfo=UTC),
                last_seen=now,
                confidence=0.91,
            ),
        ),
    )
    narrative = GroundedNarrative(
        finding_id=finding_id,
        title="Shared IP address",
        summary="The shared IP is backed by one Evidence record.",
        claims=(
            GroundedClaim(
                text="Incident A communicates with 192.0.2.10.",
                relationship_id=relationship_id,
                evidence_id=evidence_id,
                confidence=0.91,
            ),
        ),
        gaps=(),
        grounded=True,
    )
    return report, narrative, now


@pytest.mark.parametrize(
    ("platform", "event_type"),
    [
        (
            IntegrationPlatform.AI_SOC_DASHBOARD,
            "threatgraph.correlation",
        ),
        (
            IntegrationPlatform.AUTOPENTEST_AI,
            "threatgraph.security_context",
        ),
        (
            IntegrationPlatform.SENTINEL_FLOW,
            "threatgraph.incident_signal",
        ),
    ],
)
def test_platform_export_preserves_evidence_grounding(
    platform: IntegrationPlatform,
    event_type: str,
) -> None:
    report, narrative, now = _report()

    export = build_platform_export(
        platform,
        report,
        (narrative,),
        generated_at=now,
        partial=True,
    )

    assert export.schema_version == "1.0"
    assert export.platform == platform
    assert export.partial is True
    assert export.findings[0].event_type == event_type
    assert export.findings[0].evidence_ids == report.findings[0].evidence_ids
    assert export.findings[0].claims == ("Incident A communicates with 192.0.2.10.",)
    assert export.findings[0].grounded is True


def test_platform_export_requires_a_narrative_for_every_finding() -> None:
    report, _, now = _report()

    with pytest.raises(
        ValueError,
        match="every finding must have exactly one grounded narrative",
    ):
        build_platform_export(
            IntegrationPlatform.SENTINEL_FLOW,
            report,
            (),
            generated_at=now,
        )
