from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from fastapi.testclient import TestClient
from neo4j import AsyncDriver

from threatgraph.api.main import create_app
from threatgraph.config import Settings
from threatgraph.graph.models import EntityType, GraphEntity, GraphPage
from threatgraph.graph.repository import GraphQueryRepository
from threatgraph.infrastructure import Infrastructure
from threatgraph.infrastructure.health import ReadinessReport


class StubReadinessChecker:
    def __init__(self, report: ReadinessReport) -> None:
        self.report = report

    async def check(self) -> ReadinessReport:
        return self.report


class StubGraphRepository:
    def __init__(self, page: GraphPage) -> None:
        self.page = page
        self.calls: list[tuple[UUID, int, int]] = []

    async def get_subgraph(
        self,
        workspace_id: UUID,
        limit: int,
        offset: int,
    ) -> GraphPage:
        self.calls.append((workspace_id, limit, offset))
        return self.page


def build_report(status: str) -> ReadinessReport:
    component_status = "up" if status == "ready" else "down"
    return ReadinessReport.model_validate(
        {
            "status": status,
            "components": {
                "postgres": {"status": component_status},
                "neo4j": {"status": component_status},
                "redis": {"status": component_status},
            },
        }
    )


def test_liveness_and_ready_health_routes() -> None:
    app = create_app(Settings(), StubReadinessChecker(build_report("ready")))

    with TestClient(app) as client:
        live_response = client.get("/api/v1/health/live")
        ready_response = client.get("/api/v1/health/ready")

    assert live_response.status_code == 200
    assert live_response.json() == {
        "status": "ok",
        "service": "threatgraph-api",
        "version": "0.1.0",
    }
    assert ready_response.status_code == 200
    assert ready_response.json()["status"] == "ready"


def test_readiness_returns_sanitized_service_unavailable() -> None:
    app = create_app(Settings(), StubReadinessChecker(build_report("degraded")))

    with TestClient(app) as client:
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "degraded",
        "components": {
            "postgres": {"status": "down"},
            "neo4j": {"status": "down"},
            "redis": {"status": "down"},
        },
    }


def test_cors_allows_configured_web_origin() -> None:
    app = create_app(Settings(), StubReadinessChecker(build_report("ready")))

    with TestClient(app) as client:
        response = client.options(
            "/api/v1/health/live",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


class ClosableInfrastructure:
    def __init__(self) -> None:
        self.closed = False
        self.neo4j = cast(AsyncDriver, object())

    async def close(self) -> None:
        self.closed = True


def test_default_lifespan_creates_and_closes_infrastructure() -> None:
    resource = ClosableInfrastructure()
    received_settings: list[Settings] = []

    def factory(settings: Settings) -> Infrastructure:
        received_settings.append(settings)
        return cast(Infrastructure, resource)

    settings = Settings()
    app = create_app(settings=settings, infrastructure_factory=factory)

    with TestClient(app) as client:
        response = client.get("/api/v1/health/live")

    assert response.status_code == 200
    assert received_settings == [settings]
    assert resource.closed is True


def test_graph_query_is_paginated_and_masks_sensitive_entities() -> None:
    workspace_id = UUID("20000000-0000-4000-8000-000000000001")
    now = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    page = GraphPage(
        nodes=[
            GraphEntity(
                id=UUID("20000000-0000-4000-8000-000000000002"),
                workspace_id=workspace_id,
                entity_type=EntityType.IP_ADDRESS,
                key="203.0.113.9",
                name="Sensitive address",
                sensitive=True,
                properties={"asn": "AS64500"},
                created_at=now,
                updated_at=now,
            ),
            GraphEntity(
                id=UUID("20000000-0000-4000-8000-000000000003"),
                workspace_id=workspace_id,
                entity_type=EntityType.ASSET,
                key="asset-01",
                name="Endpoint 01",
                properties={"os": "Linux"},
                created_at=now,
                updated_at=now,
            ),
        ],
        relationships=[],
        total_nodes=8,
        limit=2,
        offset=4,
    )
    repository = StubGraphRepository(page)
    app = create_app(
        Settings(),
        StubReadinessChecker(build_report("ready")),
        graph_repository=cast(GraphQueryRepository, repository),
    )

    with TestClient(app) as client:
        response = client.get(f"/api/v1/workspaces/{workspace_id}/graph?limit=2&offset=4")

    assert response.status_code == 200
    assert repository.calls == [(workspace_id, 2, 4)]
    body = response.json()
    assert body["nodes"][0]["key"] == "[masked]"
    assert body["nodes"][0]["name"] == "Sensitive IPAddress"
    assert body["nodes"][0]["properties"] == {}
    assert body["nodes"][1]["key"] == "asset-01"
    assert body["next_offset"] == 6


def test_graph_query_reports_unavailable_repository_and_validates_limits() -> None:
    workspace_id = UUID("20000000-0000-4000-8000-000000000001")
    app = create_app(Settings(), StubReadinessChecker(build_report("ready")))

    with TestClient(app) as client:
        unavailable = client.get(f"/api/v1/workspaces/{workspace_id}/graph")
        invalid = client.get(f"/api/v1/workspaces/{workspace_id}/graph?limit=201")

    assert unavailable.status_code == 503
    assert unavailable.json() == {"detail": "graph repository is unavailable"}
    assert invalid.status_code == 422
