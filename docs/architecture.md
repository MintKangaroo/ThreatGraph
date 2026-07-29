# Architecture

## Foundation topology

The React/Vite web shell talks only to the FastAPI service. FastAPI owns synchronous request
boundaries, bounded graph analysis, and readiness reporting. Celery workers provide the
asynchronous ingestion execution boundary. Both backend processes receive typed configuration and
use the same Redis broker; API-managed infrastructure clients connect to PostgreSQL, Neo4j, and
Redis.

PostgreSQL is reserved for transactional metadata, workspaces, jobs, and integration state. Neo4j
is reserved for threat entities and evidence-backed relationships. The `graph-init` Compose
service installs Neo4j constraints and indexes before API and worker startup. Redis is ephemeral
coordination infrastructure, not a system of record.

## Process boundaries

- `threatgraph.api` contains the HTTP application factory, health routes, bounded graph exploration,
  correlation, narratives, and platform export routes.
- `threatgraph.worker` contains the Celery application for deployment-specific background jobs.
- `threatgraph.infrastructure` owns client construction, bounded readiness checks, and shutdown.
- `threatgraph.graph.models` owns strict entity and relationship invariants without vendor code.
- `threatgraph.graph.repository` defines the storage protocol and its Neo4j implementation.
- `threatgraph.graph.schema` contains idempotent constraints and query-supporting indexes.
- `threatgraph.stix` validates STIX 2.1 bundles, preserves source objects per workspace, maps
  supported objects and relationships, and exposes an async TAXII source boundary.
- `threatgraph.attack` normalizes official ATT&CK and Sigma technique identities.
- `threatgraph.correlation` runs deterministic time-window, shared-pivot, and technique-chain rules.
- `threatgraph.narrative` turns findings into claim-level explanations without inventing facts.
- `threatgraph.platforms` creates versioned AI-SOC, AutoPentest AI, and SentinelFlow envelopes.
- `threatgraph.config` is the environment-to-runtime trust boundary.
- `web` is an independently built React investigation dashboard. It starts with a safe demo graph
  and can load graph and correlation data for a configured workspace through the API.

Domain policy does not depend on FastAPI, SQLAlchemy, Celery, or vendor SDKs. The Neo4j repository
depends inward on typed graph models and the write and query repository protocols. Every read and
mutation matches `workspace_id`, and relationship creation additionally matches an `Evidence` node
in that workspace. Graph responses are bounded and sensitive entities are masked at the HTTP
boundary. STIX imports use deterministic IDs and create an Evidence node for every imported
relationship. Correlation results preserve relationship and Evidence IDs through narrative and
platform-export boundaries.

## Security and reliability defaults

- Development data services bind to loopback, and all supplied secrets are explicitly local-only.
- Configuration secrets use redacted values in Python representations.
- Readiness checks are concurrent, time-bounded, and return sanitized component states.
- CORS is limited to configured origins and read-only foundation endpoints.
- Celery accepts JSON serialization only.
- Caller-supplied graph properties cannot override identity, workspace, evidence, or time fields.
- Neo4j uniqueness constraints protect entity IDs and identity keys within each workspace.
- Graph expansion and shortest-path traversal have explicit maximum depth and result limits.
- Correlation windows are limited to 30 days and scan a bounded 200-entity page.
- Containers run application processes as an unprivileged user where the base image permits it.
