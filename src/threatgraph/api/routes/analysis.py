"""Evidence-backed correlation and narrative routes."""

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request
from pydantic import AwareDatetime, BaseModel

from threatgraph.api.dependencies import get_graph_repository
from threatgraph.api.routes.graph import _mask_sensitive_entities
from threatgraph.correlation import CorrelationReport, GraphCorrelator
from threatgraph.narrative import GroundedNarrative, build_grounded_narrative
from threatgraph.platforms import (
    IntegrationPlatform,
    PlatformExport,
    build_platform_export,
)

router = APIRouter(prefix="/workspaces/{workspace_id}/analysis", tags=["analysis"])


class AnalysisResponse(BaseModel):
    """Correlation report with one Evidence-grounded narrative per finding."""

    report: CorrelationReport
    narratives: tuple[GroundedNarrative, ...]
    truncated: bool


@router.get("/correlations", response_model=AnalysisResponse)
async def get_correlations(
    request: Request,
    workspace_id: UUID,
    window_hours: int = Query(default=24, ge=1, le=720),
    as_of: Annotated[AwareDatetime | None, Query()] = None,
) -> AnalysisResponse:
    """Correlate the latest bounded workspace graph and explain every finding."""

    return await _analyze_workspace(request, workspace_id, window_hours, as_of)


@router.get("/exports/{platform}", response_model=PlatformExport)
async def export_correlations(
    request: Request,
    workspace_id: UUID,
    platform: IntegrationPlatform,
    window_hours: int = Query(default=24, ge=1, le=720),
    as_of: Annotated[AwareDatetime | None, Query()] = None,
) -> PlatformExport:
    """Return a versioned evidence-backed envelope for a supported platform."""

    result = await _analyze_workspace(request, workspace_id, window_hours, as_of)
    return build_platform_export(
        platform,
        result.report,
        result.narratives,
        generated_at=result.report.window_end,
        partial=result.truncated,
    )


async def _analyze_workspace(
    request: Request,
    workspace_id: UUID,
    window_hours: int,
    as_of: datetime | None,
) -> AnalysisResponse:
    repository = get_graph_repository(request)
    window_end = as_of or datetime.now(UTC)
    window = timedelta(hours=window_hours)
    page = await repository.get_subgraph_in_range(
        workspace_id,
        window_end - window,
        window_end,
        200,
        0,
    )
    public_page = _mask_sensitive_entities(page)
    report = GraphCorrelator().correlate(
        workspace_id,
        public_page.nodes,
        public_page.relationships,
        window=window,
        as_of=window_end,
    )
    narratives = tuple(
        build_grounded_narrative(
            finding,
            public_page.nodes,
            public_page.relationships,
        )
        for finding in report.findings
    )
    return AnalysisResponse(
        report=report,
        narratives=narratives,
        truncated=page.total_nodes > len(page.nodes),
    )
