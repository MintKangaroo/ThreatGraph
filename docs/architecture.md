# Architecture

## Foundation topology

The React/Vite web shell talks only to the FastAPI service. FastAPI owns synchronous request
boundaries and readiness reporting. Celery workers provide the future asynchronous ingestion and
correlation boundary. Both backend processes receive typed configuration and use the same Redis
broker; API-managed infrastructure clients connect to PostgreSQL, Neo4j, and Redis.

PostgreSQL is reserved for transactional metadata, workspaces, jobs, and integration state. Neo4j
is reserved for threat entities and evidence-backed relationships. No schema is installed in this
milestone. Redis is ephemeral coordination infrastructure, not a system of record.

## Process boundaries

- `threatgraph.api` contains the HTTP application factory and routes.
- `threatgraph.worker` contains the Celery application; task modules arrive with ingestion work.
- `threatgraph.infrastructure` owns client construction, bounded readiness checks, and shutdown.
- `threatgraph.config` is the environment-to-runtime trust boundary.
- `web` is an independently built React application.

Domain policy must not depend on FastAPI, SQLAlchemy, Celery, or vendor SDKs. Later repositories
will depend inward on domain interfaces. Workspace isolation, evidence requirements, IOC
deduplication, masking, and pagination must be enforced in the domain and repository layers rather
than delegated to the UI.

## Security and reliability defaults

- Development data services bind to loopback, and all supplied secrets are explicitly local-only.
- Configuration secrets use redacted values in Python representations.
- Readiness checks are concurrent, time-bounded, and return sanitized component states.
- CORS is limited to configured origins and read-only foundation endpoints.
- Celery accepts JSON serialization only.
- Containers run application processes as an unprivileged user where the base image permits it.
