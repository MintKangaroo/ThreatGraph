# ThreatGraph

ThreatGraph is the graph-analysis layer shared by AI-SOC Dashboard, AutoPentest AI, and
SentinelFlow. It will correlate assets, events, indicators, vulnerabilities, threat actors,
and MITRE ATT&CK techniques while preserving evidence and workspace boundaries.

> Status: platform foundation. Graph schemas, ingestion, correlation, visualization, and AI
> narratives are intentionally deferred to their dedicated milestones.

## Foundation services

- FastAPI service with liveness and dependency-readiness endpoints
- PostgreSQL metadata store and Neo4j graph store
- Redis-backed Celery worker runtime
- React and Vite web shell
- Docker Compose development environment with persistent service volumes
- Python and web quality gates in CI

## Quick start

Docker Compose is the supported way to run the complete local foundation:

```bash
cp .env.example .env
docker compose up --build
```

Open the web shell at <http://localhost:5173>, API documentation at
<http://localhost:8000/docs>, and Neo4j Browser at <http://localhost:7474>.
Development data is stored in named Docker volumes. Stop services with `docker compose down`;
add `--volumes` only when you deliberately want to delete that local data.

The example credentials are for an isolated local machine only. Replace every password before
using a shared or non-development environment. Infrastructure ports bind to loopback by default.

## Health endpoints

- `GET /api/v1/health/live` checks whether the API process is serving requests.
- `GET /api/v1/health/ready` checks PostgreSQL, Neo4j, and Redis with a bounded timeout.

Readiness failures return only `up` or `down` component states; connection details and errors are
not exposed.

## Local quality checks

Python 3.12 and Node.js 20 or later are required when working outside containers.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
make install web-install
make check
```

Run only the Python or web portions with `make test` and `make web-test` respectively.

## Current boundaries

This milestone does not create graph labels, relationship types, database tables, importers,
queries, or AI output. No target scanning or offensive action is implemented. See
[docs/architecture.md](docs/architecture.md), [docs/roadmap.md](docs/roadmap.md), and
[SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This project is licensed under the MIT License.
