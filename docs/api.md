# API

The foundation API exposes process and infrastructure health under `/api/v1`.

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

Connection errors are deliberately not included. Graph query endpoints, workspace authorization,
pagination, and IOC masking are introduced with their respective domain and API milestones.
