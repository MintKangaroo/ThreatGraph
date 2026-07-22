from typing import cast

from fastapi.testclient import TestClient

from threatgraph.api.main import create_app
from threatgraph.config import Settings
from threatgraph.infrastructure import Infrastructure
from threatgraph.infrastructure.health import ReadinessReport


class StubReadinessChecker:
    def __init__(self, report: ReadinessReport) -> None:
        self.report = report

    async def check(self) -> ReadinessReport:
        return self.report


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
