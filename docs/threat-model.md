# Threat Model

## Assets

Operator authorization records, target allowlists, scan or analysis results, audit
events, service credentials, and integration tokens are sensitive assets.

## Trust boundaries

Current boundaries include HTTP clients, Celery workers, PostgreSQL, Neo4j, Redis, and the
container network. Future external tools and third-party integrations add further boundaries.
All data crossing a boundary is untrusted.

## Initial controls

- Data-service ports bind to loopback in the development Compose environment
- Secrets excluded through `.gitignore`; placeholders only in `.env.example`
- API readiness errors are sanitized and time-bounded
- Graph reads and writes always include `workspace_id`
- Relationship writes require an existing `Evidence` node in the same workspace
- Reserved graph properties cannot be overridden by untrusted attributes
- Celery accepts JSON serialization only
- Read-only GitHub Actions permissions
- Static analysis includes common Python security rules

Before target-facing features ship, a central validator must accept only localhost,
RFC1918/Docker networks, or explicit allowlist entries; reject public and unauthorized
targets; prevent DNS rebinding and ambiguous address forms; and emit redacted audit logs.
