"""Workspace-scoped graph query routes for the dashboard."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import AwareDatetime, BaseModel, Field

from threatgraph.api.dependencies import get_graph_repository
from threatgraph.graph.models import (
    EntityType,
    GraphEntity,
    GraphPage,
    GraphPath,
    GraphRelationship,
)

router = APIRouter(prefix="/workspaces/{workspace_id}/graph", tags=["graph"])


class GraphPageResponse(BaseModel):
    """Public graph page with explicit pagination metadata."""

    nodes: list[GraphEntity]
    relationships: list[GraphRelationship]
    total_nodes: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)
    next_offset: int | None = Field(default=None, ge=0)


class GraphPathResponse(BaseModel):
    """Public shortest-path response."""

    nodes: list[GraphEntity]
    relationships: list[GraphRelationship]
    length: int = Field(ge=0)


@router.get("", response_model=GraphPageResponse)
async def get_workspace_graph(
    request: Request,
    workspace_id: UUID,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    since: Annotated[AwareDatetime | None, Query()] = None,
    until: Annotated[AwareDatetime | None, Query()] = None,
) -> GraphPageResponse:
    """Return one bounded, workspace-isolated subgraph page."""

    repository = get_graph_repository(request)
    if (since is None) != (until is None):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="since and until must be provided together",
        )
    if since is not None and until is not None:
        page = await repository.get_subgraph_in_range(
            workspace_id,
            since,
            until,
            limit,
            offset,
        )
    else:
        page = await repository.get_subgraph(workspace_id, limit, offset)
    return _page_response(page)


@router.get(
    "/entities/{entity_id}/neighborhood",
    response_model=GraphPageResponse,
)
async def get_entity_neighborhood(
    request: Request,
    workspace_id: UUID,
    entity_id: UUID,
    depth: int = Query(default=1, ge=1, le=5),
    limit: int = Query(default=100, ge=1, le=200),
    since: Annotated[AwareDatetime | None, Query()] = None,
) -> GraphPageResponse:
    """Expand a bounded graph neighborhood from one entity."""

    repository = get_graph_repository(request)
    page = await repository.get_neighborhood(
        workspace_id,
        entity_id,
        depth,
        limit,
        since,
    )
    if not page.nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="entity was not found in the workspace",
        )
    return _page_response(page)


@router.get("/paths/shortest", response_model=GraphPathResponse)
async def get_shortest_path(
    request: Request,
    workspace_id: UUID,
    source_entity_id: UUID,
    target_entity_id: UUID,
    max_depth: int = Query(default=8, ge=1, le=8),
    since: Annotated[AwareDatetime | None, Query()] = None,
) -> GraphPathResponse:
    """Return a bounded shortest path between two workspace entities."""

    repository = get_graph_repository(request)
    path = await repository.get_shortest_path(
        workspace_id,
        source_entity_id,
        target_entity_id,
        max_depth,
        since,
    )
    if path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no path was found in the workspace",
        )
    return _path_response(path)


@router.get("/incidents/{incident_id}", response_model=GraphPageResponse)
async def get_incident_subgraph(
    request: Request,
    workspace_id: UUID,
    incident_id: UUID,
    depth: int = Query(default=2, ge=1, le=5),
    limit: int = Query(default=100, ge=1, le=200),
    since: Annotated[AwareDatetime | None, Query()] = None,
) -> GraphPageResponse:
    """Return a bounded subgraph rooted at an Incident entity."""

    repository = get_graph_repository(request)
    incident = await repository.get_entity(workspace_id, incident_id)
    if incident is None or incident.entity_type != EntityType.INCIDENT:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="incident was not found in the workspace",
        )
    page = await repository.get_neighborhood(
        workspace_id,
        incident_id,
        depth,
        limit,
        since,
    )
    return _page_response(page)


def _page_response(page: GraphPage) -> GraphPageResponse:
    public_page = _mask_sensitive_entities(page)
    return GraphPageResponse(
        nodes=public_page.nodes,
        relationships=list(public_page.relationships),
        total_nodes=public_page.total_nodes,
        limit=public_page.limit,
        offset=public_page.offset,
        next_offset=public_page.next_offset,
    )


def _path_response(path: GraphPath) -> GraphPathResponse:
    nodes = [_mask_sensitive_entity(node) for node in path.nodes]
    return GraphPathResponse(
        nodes=nodes,
        relationships=list(path.relationships),
        length=path.length,
    )


def _mask_sensitive_entities(page: GraphPage) -> GraphPage:
    nodes = [_mask_sensitive_entity(node) for node in page.nodes]
    return page.model_copy(update={"nodes": nodes})


def _mask_sensitive_entity(node: GraphEntity) -> GraphEntity:
    if not node.sensitive:
        return node
    return node.model_copy(
        update={
            "key": "[masked]",
            "name": f"Sensitive {node.entity_type.value}",
            "properties": {},
        }
    )
