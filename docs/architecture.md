# Architecture

## Foundation topology

The React/Vite web shell talks only to the FastAPI service. FastAPI owns synchronous request
boundaries and readiness reporting. Celery workers provide the future asynchronous ingestion and
correlation boundary. Both backend processes receive typed configuration and use the same Redis
broker; API-managed infrastructure clients connect to PostgreSQL, Neo4j, and Redis.

PostgreSQL is reserved for transactional metadata, workspaces, jobs, and integration state. Neo4j
is reserved for threat entities and evidence-backed relationships. The `graph-init` Compose
service installs Neo4j constraints and indexes before API and worker startup. Redis is ephemeral
coordination infrastructure, not a system of record.

## Process boundaries

- `threatgraph.api` contains the HTTP application factory and routes.
- `threatgraph.worker` contains the Celery application; task modules arrive with ingestion work.
- `threatgraph.infrastructure` owns client construction, bounded readiness checks, and shutdown.
- `threatgraph.graph.models` owns strict entity and relationship invariants without vendor code.
- `threatgraph.graph.repository` defines the storage protocol and its Neo4j implementation.
- `threatgraph.graph.schema` contains idempotent constraints and query-supporting indexes.
- `threatgraph.config` is the environment-to-runtime trust boundary.
- `web` is an independently built React application.

Domain policy does not depend on FastAPI, SQLAlchemy, Celery, or vendor SDKs. The Neo4j repository
depends inward on typed graph models and the `GraphRepository` protocol. Every read and mutation
matches `workspace_id`, and relationship creation additionally matches an `Evidence` node in that
workspace. IOC-specific normalization, masking, and query pagination remain later milestones.

## Security and reliability defaults

- Development data services bind to loopback, and all supplied secrets are explicitly local-only.
- Configuration secrets use redacted values in Python representations.
- Readiness checks are concurrent, time-bounded, and return sanitized component states.
- CORS is limited to configured origins and read-only foundation endpoints.
- Celery accepts JSON serialization only.
- Caller-supplied graph properties cannot override identity, workspace, evidence, or time fields.
- Neo4j uniqueness constraints protect entity IDs and identity keys within each workspace.
- Containers run application processes as an unprivileged user where the base image permits it.
