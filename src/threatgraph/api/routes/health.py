"""Liveness and dependency-readiness routes."""

from typing import Literal, cast

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from threatgraph import __version__
from threatgraph.infrastructure.health import ReadinessChecker, ReadinessReport

router = APIRouter(prefix="/health", tags=["health"])


class LivenessResponse(BaseModel):
    """Static process liveness response."""

    status: Literal["ok"] = "ok"
    service: str = "threatgraph-api"
    version: str = __version__


@router.get("/live", response_model=LivenessResponse)
async def liveness() -> LivenessResponse:
    """Report that the API process can serve requests."""

    return LivenessResponse()


@router.get(
    "/ready",
    response_model=ReadinessReport,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessReport}},
)
async def readiness(request: Request) -> JSONResponse:
    """Report connectivity to all data services with a bounded wait."""

    checker = cast(ReadinessChecker, request.app.state.readiness_checker)
    report = await checker.check()
    status_code = (
        status.HTTP_200_OK if report.status == "ready" else status.HTTP_503_SERVICE_UNAVAILABLE
    )
    return JSONResponse(status_code=status_code, content=report.model_dump(mode="json"))
