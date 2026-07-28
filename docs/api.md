# API

The API exposes process health and bounded workspace graph exploration under `/api/v1`.

## `GET /health/live`

Returns HTTP 200 while the FastAPI process can serve requests:

```json
{
  "status": "ok",
  "service": "threatgraph-api",
  "version": "0.1.0"
}
```

## `GET /health/ready`

Returns HTTP 200 with `status: ready` when PostgreSQL, Neo4j, and Redis respond. It returns HTTP
503 with `status: degraded` if any dependency fails or exceeds the configured timeout.

```json
{
  "status": "ready",
  "components": {
    "postgres": { "status": "up" },
    "neo4j": { "status": "up" },
    "redis": { "status": "up" }
  }
}
```

Connection errors are deliberately not included.

## `GET /workspaces/{workspace_id}/graph`

Returns a bounded page of entities and relationships from exactly one workspace.

Query parameters:

- `limit`: number of entities, from 1 through 200; default 100.
- `offset`: non-negative entity offset; default 0.

Only relationships whose source and target are both in the entity page are returned. Entities are
ordered by `updated_at` and `id` for deterministic pagination. A caller cannot omit the workspace
scope. Sensitive entities are represented with a `[masked]` key, a generic name, and no custom
properties.

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

The current endpoint provides the dashboard subgraph boundary. Workspace authentication and
authorization must be enforced by the deployment's identity layer before exposing the API outside
an isolated development environment.
