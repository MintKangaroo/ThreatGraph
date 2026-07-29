# Platform integrations

ThreatGraph provides a vendor-neutral, versioned export envelope for AI-SOC Dashboard,
AutoPentest AI, and SentinelFlow.

```text
GET /api/v1/workspaces/{workspace_id}/analysis/exports/{platform}
```

| Platform path | Event type |
| --- | --- |
| `ai-soc-dashboard` | `threatgraph.correlation` |
| `autopentest-ai` | `threatgraph.security_context` |
| `sentinelflow` | `threatgraph.incident_signal` |

Every `schema_version: "1.0"` envelope contains:

- platform, workspace UUID, generation time, and correlation window;
- `partial`, propagated from the bounded graph scan;
- finding ID, rule kind, severity, confidence, and entity IDs;
- Evidence IDs, grounded claim text, explicit gaps, and grounding state.

The core deliberately stops at the delivery contract. A deployment may deliver the JSON through
HTTP, a queue, or its existing integration bus without coupling graph and correlation policy to
vendor credentials or retry behavior. Platform-specific transports should treat finding IDs as
idempotency keys and reject envelopes from unauthorized workspaces.
