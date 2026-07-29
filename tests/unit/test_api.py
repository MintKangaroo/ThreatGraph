from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from fastapi.testclient import TestClient
from neo4j import AsyncDriver

from threatgraph.api.main import create_app
from threatgraph.config import Settings
from threatgraph.graph.models import (
    EntityType,
    GraphEntity,
    GraphPage,
    GraphPath,
    GraphRelationship,
    RelationshipType,
)
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
        self.range_page = page
        self.neighborhood_page = page
        self.path: GraphPath | None = None
        self.entity: GraphEntity | None = page.nodes[0] if page.nodes else None
        self.subgraph_calls: list[tuple[UUID, int, int]] = []
        self.range_calls: list[tuple[UUID, datetime, datetime, int, int]] = []
        self.neighborhood_calls: list[tuple[UUID, UUID, int, int, datetime | None]] = []
        self.path_calls: list[tuple[UUID, UUID, UUID, int, datetime | None]] = []
        self.entity_calls: list[tuple[UUID, UUID]] = []

    async def get_subgraph(
        self,
        workspace_id: UUID,
        limit: int,
        offset: int,
    ) -> GraphPage:
        self.subgraph_calls.append((workspace_id, limit, offset))
        return self.page

    async def get_subgraph_in_range(
        self,
        workspace_id: UUID,
        since: datetime,
        until: datetime,
        limit: int,
        offset: int,
    ) -> GraphPage:
        self.range_calls.append((workspace_id, since, until, limit, offset))
        return self.range_page

    async def get_neighborhood(
        self,
        workspace_id: UUID,
        entity_id: UUID,
        depth: int,
        limit: int,
        since: datetime | None,
    ) -> GraphPage:
        self.neighborhood_calls.append((workspace_id, entity_id, depth, limit, since))
        return self.neighborhood_page

    async def get_shortest_path(
        self,
        workspace_id: UUID,
        source_entity_id: UUID,
        target_entity_id: UUID,
        max_depth: int,
        since: datetime | None,
    ) -> GraphPath | None:
        self.path_calls.append(
            (
                workspace_id,
                source_entity_id,
                target_entity_id,
                max_depth,
                since,
            )
        )
        return self.path

    async def get_entity(
        self,
        workspace_id: UUID,
        entity_id: UUID,
    ) -> GraphEntity | None:
        self.entity_calls.append((workspace_id, entity_id))
        return self.entity


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
    assert repository.subgraph_calls == [(workspace_id, 2, 4)]
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


def test_graph_time_range_query_and_paired_parameter_validation() -> None:
    workspace_id = UUID("20000000-0000-4000-8000-000000000001")
    page = GraphPage(nodes=[], relationships=[], total_nodes=0, limit=10, offset=0)
    repository = StubGraphRepository(page)
    app = create_app(
        Settings(),
        StubReadinessChecker(build_report("ready")),
        graph_repository=cast(GraphQueryRepository, repository),
    )
    since = "2026-07-28T00:00:00Z"
    until = "2026-07-29T00:00:00Z"

    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/workspaces/{workspace_id}/graph",
            params={"limit": 10, "since": since, "until": until},
        )
        incomplete = client.get(
            f"/api/v1/workspaces/{workspace_id}/graph",
            params={"since": since},
        )

    assert response.status_code == 200
    assert repository.range_calls[0][0] == workspace_id
    assert repository.range_calls[0][3:] == (10, 0)
    assert incomplete.status_code == 422
    assert incomplete.json()["detail"] == "since and until must be provided together"


def test_neighborhood_shortest_path_and_incident_routes() -> None:
    workspace_id = UUID("20000000-0000-4000-8000-000000000001")
    incident_id = UUID("20000000-0000-4000-8000-000000000010")
    sensitive_id = UUID("20000000-0000-4000-8000-000000000011")
    relationship_id = UUID("20000000-0000-4000-8000-000000000012")
    evidence_id = UUID("20000000-0000-4000-8000-000000000013")
    now = datetime(2026, 7, 29, 4, 0, tzinfo=UTC)
    incident = GraphEntity(
        id=incident_id,
        workspace_id=workspace_id,
        entity_type=EntityType.INCIDENT,
        key="incident-01",
        name="INC-01",
        created_at=now,
        updated_at=now,
    )
    sensitive = GraphEntity(
        id=sensitive_id,
        workspace_id=workspace_id,
        entity_type=EntityType.IP_ADDRESS,
        key="203.0.113.7",
        sensitive=True,
        created_at=now,
        updated_at=now,
    )
    relationship = GraphRelationship(
        id=relationship_id,
        workspace_id=workspace_id,
        relationship_type=RelationshipType.COMMUNICATES_WITH,
        source_entity_id=incident_id,
        target_entity_id=sensitive_id,
        source="sensor",
        first_seen=now,
        last_seen=now,
        confidence=0.9,
        evidence_id=evidence_id,
        created_at=now,
        updated_at=now,
    )
    page = GraphPage(
        nodes=[incident, sensitive],
        relationships=[relationship],
        total_nodes=2,
        limit=100,
        offset=0,
    )
    repository = StubGraphRepository(page)
    repository.entity = incident
    repository.path = GraphPath(
        nodes=(incident, sensitive),
        relationships=(relationship,),
    )
    app = create_app(
        Settings(),
        StubReadinessChecker(build_report("ready")),
        graph_repository=cast(GraphQueryRepository, repository),
    )

    with TestClient(app) as client:
        neighborhood = client.get(
            f"/api/v1/workspaces/{workspace_id}/graph/entities/{incident_id}/neighborhood?depth=2"
        )
        path = client.get(
            f"/api/v1/workspaces/{workspace_id}/graph/paths/shortest",
            params={
                "source_entity_id": str(incident_id),
                "target_entity_id": str(sensitive_id),
                "max_depth": 4,
            },
        )
        incident_response = client.get(
            f"/api/v1/workspaces/{workspace_id}/graph/incidents/{incident_id}"
        )

    assert neighborhood.status_code == 200
    assert repository.neighborhood_calls[0][2] == 2
    assert path.status_code == 200
    assert path.json()["length"] == 1
    assert path.json()["nodes"][1]["key"] == "[masked]"
    assert incident_response.status_code == 200
    assert repository.entity_calls == [(workspace_id, incident_id)]


def test_exploration_routes_return_not_found_for_missing_results() -> None:
    workspace_id = UUID("20000000-0000-4000-8000-000000000001")
    entity_id = UUID("20000000-0000-4000-8000-000000000010")
    empty = GraphPage(nodes=[], relationships=[], total_nodes=0, limit=100, offset=0)
    repository = StubGraphRepository(empty)
    app = create_app(
        Settings(),
        StubReadinessChecker(build_report("ready")),
        graph_repository=cast(GraphQueryRepository, repository),
    )

    with TestClient(app) as client:
        neighborhood = client.get(
            f"/api/v1/workspaces/{workspace_id}/graph/entities/{entity_id}/neighborhood"
        )
        path = client.get(
            f"/api/v1/workspaces/{workspace_id}/graph/paths/shortest",
            params={
                "source_entity_id": str(entity_id),
                "target_entity_id": str(entity_id),
            },
        )
        incident = client.get(f"/api/v1/workspaces/{workspace_id}/graph/incidents/{entity_id}")

    assert neighborhood.status_code == 404
    assert path.status_code == 404
    assert incident.status_code == 404

    repository.entity = GraphEntity(
        id=entity_id,
        workspace_id=workspace_id,
        entity_type=EntityType.ASSET,
        key="asset-01",
        created_at=datetime(2026, 7, 29, 4, 0, tzinfo=UTC),
        updated_at=datetime(2026, 7, 29, 4, 0, tzinfo=UTC),
    )
    with TestClient(app) as client:
        wrong_type = client.get(f"/api/v1/workspaces/{workspace_id}/graph/incidents/{entity_id}")
    assert wrong_type.status_code == 404


def test_analysis_route_returns_grounded_correlations() -> None:
    workspace_id = UUID("21000000-0000-4000-8000-000000000001")
    now = datetime(2026, 7, 29, 5, 0, tzinfo=UTC)
    address = GraphEntity(
        id=UUID("21000000-0000-4000-8000-000000000002"),
        workspace_id=workspace_id,
        entity_type=EntityType.IP_ADDRESS,
        key="203.0.113.8",
        name="Sensitive address",
        sensitive=True,
        created_at=now,
        updated_at=now,
    )
    neighbors = [
        GraphEntity(
            id=UUID(f"21000000-0000-4000-8000-{index:012d}"),
            workspace_id=workspace_id,
            entity_type=entity_type,
            key=name.lower(),
            name=name,
            created_at=now,
            updated_at=now,
        )
        for index, entity_type, name in (
            (3, EntityType.ASSET, "Endpoint"),
            (4, EntityType.INCIDENT, "INC-8"),
            (5, EntityType.DOMAIN, "cdn.example"),
        )
    ]
    relationships = [
        GraphRelationship(
            id=UUID(f"22000000-0000-4000-8000-{index:012d}"),
            workspace_id=workspace_id,
            relationship_type=RelationshipType.RELATED_TO,
            source_entity_id=address.id,
            target_entity_id=neighbor.id,
            source="correlation-test",
            first_seen=now,
            last_seen=now,
            confidence=0.95,
            evidence_id=UUID(f"23000000-0000-4000-8000-{index:012d}"),
            created_at=now,
            updated_at=now,
        )
        for index, neighbor in enumerate(neighbors, start=1)
    ]
    page = GraphPage(
        nodes=[address, *neighbors],
        relationships=relationships,
        total_nodes=5,
        limit=200,
        offset=0,
    )
    repository = StubGraphRepository(page)
    app = create_app(
        Settings(),
        StubReadinessChecker(build_report("ready")),
        graph_repository=cast(GraphQueryRepository, repository),
    )

    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/workspaces/{workspace_id}/analysis/correlations",
            params={"window_hours": 24, "as_of": now.isoformat()},
        )
        export = client.get(
            f"/api/v1/workspaces/{workspace_id}/analysis/exports/sentinelflow",
            params={"window_hours": 24, "as_of": now.isoformat()},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["truncated"] is True
    assert body["report"]["findings"][0]["title"] == ("Shared IPAddress: Sensitive IPAddress")
    assert body["narratives"][0]["grounded"] is True
    assert len(body["narratives"][0]["claims"]) == 3
    assert repository.range_calls[0][3:] == (200, 0)
    assert export.status_code == 200
    assert export.json()["platform"] == "sentinelflow"
    assert export.json()["findings"][0]["event_type"] == "threatgraph.incident_signal"
    assert export.json()["findings"][0]["grounded"] is True
