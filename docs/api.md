# API

ThreatGraph exposes health, bounded workspace graph exploration, deterministic correlation, and
platform export routes under `/api/v1`. Every graph and analysis route requires a workspace UUID.

## Health

### `GET /health/live`

Returns HTTP 200 while the FastAPI process can serve requests:

```json
{
  "status": "ok",
  "service": "threatgraph-api",
  "version": "0.1.0"
}
```

### `GET /health/ready`

Returns HTTP 200 with `status: ready` when PostgreSQL, Neo4j, and Redis respond. It returns HTTP 503
with `status: degraded` when a dependency fails or exceeds the configured timeout. Connection
strings, credentials, and exception messages are deliberately omitted.

## Graph exploration

### `GET /workspaces/{workspace_id}/graph`

Returns a deterministic, bounded workspace page.

- `limit`: 1–200, default 100.
- `offset`: non-negative, default 0.
- `since`, `until`: optional timezone-aware timestamps that must be supplied together.

Only relationships whose endpoints are in the returned page are included. Sensitive entities use
the key `[masked]`, a generic name, and empty custom properties.

```json
{
  "nodes": [],
  "relationships": [],
  "total_nodes": 0,
  "limit": 100,
  "offset": 0,
  "next_offset": null
}
```

### `GET /workspaces/{workspace_id}/graph/entities/{entity_id}/neighborhood`

Expands an entity neighborhood inside the same workspace.

- `depth`: 1–5, default 1.
- `limit`: 1–200, default 100.
- `since`: optional lower observation boundary.

The dashboard requests depth 2 when an analyst double-clicks a live node. A missing or cross-
workspace entity returns HTTP 404.

### `GET /workspaces/{workspace_id}/graph/incidents/{incident_id}`

Returns a bounded neighborhood rooted at an `Incident`. It accepts the same `depth`, `limit`, and
`since` parameters as the entity-neighborhood route. A non-Incident root returns HTTP 404.

### `GET /workspaces/{workspace_id}/graph/paths/shortest`

Returns the shortest workspace path and its ordered nodes and relationships.

- `source_entity_id`, `target_entity_id`: required UUIDs.
- `max_depth`: 1–8, default 8.
- `since`: optional lower observation boundary.

No path, a cross-workspace endpoint, or a missing endpoint returns HTTP 404.

## Correlation and explanations

### `GET /workspaces/{workspace_id}/analysis/correlations`

Runs deterministic shared-indicator, shared-context, and ATT&CK-chain rules on the latest bounded
workspace graph.

- `window_hours`: 1–720, default 24.
- `as_of`: optional timezone-aware end time; useful for replay and deterministic tests.

The response contains the correlation report plus one grounded narrative per finding. Every claim
cites its relationship ID, Evidence ID, and confidence. `gaps` explicitly lists anything that
could not be verified. `truncated: true` means more entities existed than the bounded analysis page.

```json
{
  "report": {
    "workspace_id": "00000000-0000-4000-8000-000000000001",
    "window_start": "2026-07-28T00:00:00Z",
    "window_end": "2026-07-29T00:00:00Z",
    "scanned_entities": 4,
    "scanned_relationships": 3,
    "findings": []
  },
  "narratives": [],
  "truncated": false
}
```

### `GET /workspaces/{workspace_id}/analysis/exports/{platform}`

Builds a versioned delivery envelope from the same bounded analysis. Supported platform path values
are:

- `ai-soc-dashboard`
- `autopentest-ai`
- `sentinelflow`

The envelope retains workspace and time-window scope, finding/entity/Evidence identities,
claim text, gaps, grounding state, and partial-result metadata. See
[Platform integrations](integrations.md) for the contract.

## Deployment boundary

The repository enforces workspace scoping, query limits, masking, and evidence integrity. The
deployment identity layer must authenticate callers and authorize access to the requested
`workspace_id` before the API is exposed outside an isolated development environment.
