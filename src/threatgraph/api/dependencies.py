"""Shared HTTP dependency boundaries."""

from typing import cast

from fastapi import HTTPException, Request, status

from threatgraph.graph.repository import GraphQueryRepository


def get_graph_repository(request: Request) -> GraphQueryRepository:
    """Return the configured graph repository or a sanitized 503."""

    repository = getattr(request.app.state, "graph_repository", None)
    if repository is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="graph repository is unavailable",
        )
    return cast(GraphQueryRepository, repository)
