"""Typed outbound contracts for ThreatGraph platform integrations."""

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from threatgraph.correlation import (
    CorrelationKind,
    CorrelationReport,
    FindingSeverity,
)
from threatgraph.graph.models import GraphModel
from threatgraph.narrative import GroundedNarrative


class IntegrationPlatform(StrEnum):
    """Supported downstream security platforms."""

    AI_SOC_DASHBOARD = "ai-soc-dashboard"
    AUTOPENTEST_AI = "autopentest-ai"
    SENTINEL_FLOW = "sentinelflow"


class PlatformFinding(GraphModel):
    """Portable evidence-backed finding sent to a downstream platform."""

    id: UUID
    event_type: str = Field(min_length=1, max_length=128)
    kind: CorrelationKind
    severity: FindingSeverity
    title: str
    summary: str
    confidence: float = Field(ge=0, le=1)
    entity_ids: tuple[UUID, ...]
    evidence_ids: tuple[UUID, ...]
    claims: tuple[str, ...]
    gaps: tuple[str, ...]
    grounded: bool


class PlatformExport(GraphModel):
    """Versioned, workspace-scoped delivery envelope."""

    schema_version: Literal["1.0"] = "1.0"
    platform: IntegrationPlatform
    workspace_id: UUID
    generated_at: AwareDatetime
    window_start: AwareDatetime
    window_end: AwareDatetime
    partial: bool
    findings: tuple[PlatformFinding, ...]


_EVENT_TYPES = {
    IntegrationPlatform.AI_SOC_DASHBOARD: "threatgraph.correlation",
    IntegrationPlatform.AUTOPENTEST_AI: "threatgraph.security_context",
    IntegrationPlatform.SENTINEL_FLOW: "threatgraph.incident_signal",
}


def build_platform_export(
    platform: IntegrationPlatform,
    report: CorrelationReport,
    narratives: tuple[GroundedNarrative, ...],
    *,
    generated_at: datetime,
    partial: bool = False,
) -> PlatformExport:
    """Convert a complete correlation result into a stable integration envelope."""

    narrative_map = {narrative.finding_id: narrative for narrative in narratives}
    finding_ids = {finding.id for finding in report.findings}
    if set(narrative_map) != finding_ids:
        raise ValueError("every finding must have exactly one grounded narrative")
    records = tuple(
        PlatformFinding(
            id=finding.id,
            event_type=_EVENT_TYPES[platform],
            kind=finding.kind,
            severity=finding.severity,
            title=narrative_map[finding.id].title,
            summary=narrative_map[finding.id].summary,
            confidence=finding.confidence,
            entity_ids=finding.entity_ids,
            evidence_ids=finding.evidence_ids,
            claims=tuple(claim.text for claim in narrative_map[finding.id].claims),
            gaps=narrative_map[finding.id].gaps,
            grounded=narrative_map[finding.id].grounded,
        )
        for finding in report.findings
    )
    return PlatformExport(
        platform=platform,
        workspace_id=report.workspace_id,
        generated_at=generated_at,
        window_start=report.window_start,
        window_end=report.window_end,
        partial=partial,
        findings=records,
    )
