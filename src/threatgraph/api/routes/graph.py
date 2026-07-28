"""Workspace-scoped graph query routes for the dashboard."""

from typing import cast
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from threatgraph.graph.models import GraphEntity, GraphPage, GraphRelationship
from threatgraph.graph.repository import GraphQueryRepository

router = APIRouter(prefix="/workspaces/{workspace_id}/graph", tags=["graph"])


class GraphPageResponse(BaseModel):
    """Public graph page with explicit pagination metadata."""

    nodes: list[GraphEntity]
    relationships: list[GraphRelationship]
    total_nodes: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)
    next_offset: int | None = Field(default=None, ge=0)


@router.get("", response_model=GraphPageResponse)
async def get_workspace_graph(
    request: Request,
    workspace_id: UUID,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> GraphPageResponse:
    """Return one bounded, workspace-isolated subgraph page."""

    repository = getattr(request.app.state, "graph_repository", None)
    if repository is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="graph repository is unavailable",
        )
    page = await cast(GraphQueryRepository, repository).get_subgraph(workspace_id, limit, offset)
    public_page = _mask_sensitive_entities(page)
    return GraphPageResponse(
        nodes=public_page.nodes,
        relationships=list(public_page.relationships),
        total_nodes=public_page.total_nodes,
        limit=public_page.limit,
        offset=public_page.offset,
        next_offset=public_page.next_offset,
    )


def _mask_sensitive_entities(page: GraphPage) -> GraphPage:
    nodes = [
        node.model_copy(
            update={
                "key": "[masked]",
                "name": f"Sensitive {node.entity_type.value}",
                "properties": {},
            }
        )
        if node.sensitive
        else node
        for node in page.nodes
    ]
    return page.model_copy(update={"nodes": nodes})
