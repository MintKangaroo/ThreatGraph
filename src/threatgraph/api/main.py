"""FastAPI application factory and service lifecycle."""

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from threatgraph import __version__
from threatgraph.api.routes.graph import router as graph_router
from threatgraph.api.routes.health import router as health_router
from threatgraph.config import Settings, get_settings
from threatgraph.graph.repository import GraphQueryRepository, Neo4jGraphRepository
from threatgraph.infrastructure import Infrastructure
from threatgraph.infrastructure.health import InfrastructureReadinessChecker, ReadinessChecker

InfrastructureFactory = Callable[[Settings], Infrastructure]


def create_app(
    settings: Settings | None = None,
    readiness_checker: ReadinessChecker | None = None,
    infrastructure_factory: InfrastructureFactory = Infrastructure.from_settings,
    graph_repository: GraphQueryRepository | None = None,
) -> FastAPI:
    """Build an API instance with injectable infrastructure for deterministic tests."""

    resolved_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        infrastructure: Infrastructure | None = None
        checker = readiness_checker
        if checker is None:
            infrastructure = infrastructure_factory(resolved_settings)
            checker = InfrastructureReadinessChecker(
                infrastructure,
                resolved_settings.health_check_timeout_seconds,
            )
        repository = graph_repository
        if repository is None and infrastructure is not None:
            repository = Neo4jGraphRepository(
                infrastructure.neo4j,
                resolved_settings.neo4j_database,
            )
        application.state.readiness_checker = checker
        application.state.graph_repository = repository
        yield
        if infrastructure is not None:
            await infrastructure.close()

    api = FastAPI(
        title=resolved_settings.app_name,
        version=__version__,
        lifespan=lifespan,
    )
    api.add_middleware(
        CORSMiddleware,
        allow_origins=resolved_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["*"],
    )
    api.include_router(health_router, prefix=resolved_settings.api_prefix)
    api.include_router(graph_router, prefix=resolved_settings.api_prefix)
    return api


app = create_app()
