# Roadmap

**MVP Core status: 100% complete (10/10 milestones).**

The initial ThreatGraph delivery milestones are complete.

1. **Platform foundation (complete):** FastAPI, PostgreSQL, Neo4j, Redis/Celery, React, Compose, and
   health checks.
2. **Graph schema and repositories (complete):** typed entities, evidence-backed edges, constraints,
   indexes, idempotent upserts, and workspace isolation.
3. **STIX 2.1 (complete):** bundle import/export, workspace-scoped preservation, supported object
   mapping, relationship evidence, custom ATT&CK properties, and a TAXII adapter boundary.
4. **IOC pipeline (complete):** normalization, stable identity keys, deduplication, and optional
   masking.
5. **MITRE ATT&CK (complete):** canonical technique and sub-technique IDs, official STIX
   attack-pattern mapping, tactics/platform metadata, and Sigma tag mapping.
6. **Correlation (complete):** bounded time windows, common IOC/asset/identity pivots, and
   incident-to-technique chain rules with deterministic finding IDs.
7. **Graph query API (complete):** pagination, time-range subgraphs, entity neighborhoods, incident
   subgraphs, bounded shortest paths, and sensitive entity masking.
8. **Visualization (complete):** interactive explorer, search, filters, critical path, time slider,
   evidence panel, grounded correlation summary, JSON export, live/demo modes, and server-side
   two-hop expansion.
9. **Grounded narratives (complete):** deterministic finding explanations, claim-level Evidence
   IDs and confidence, and explicit missing-evidence gaps.
10. **Platform adapters (complete):** versioned export envelopes for AI-SOC Dashboard,
    AutoPentest AI, and SentinelFlow with workspace, evidence, and partial-result metadata.

Future work is release-oriented: deployment-specific authentication/authorization, production
TAXII credentials, downstream delivery transports, and scale testing against deployment-sized
datasets. These concerns remain outside the repository's vendor-neutral core.

## Post-MVP deployment cycle

These items are planned deployment integrations, not missing MVP core functionality.

| Priority | Workstream | Completion criteria |
| --- | --- | --- |
| P1 | Identity and workspace authorization | The selected IdP authenticates callers, every workspace route rejects unauthorized access, and cross-workspace tests pass. |
| P1 | Production TAXII and delivery transports | Credential rotation, pagination, retry/backoff, idempotency, and dead-letter behavior are tested against the selected systems. |
| P2 | Scale and performance validation | Representative datasets have documented API latency, Neo4j query plans, correlation truncation behavior, and resource limits. |
| P2 | Operational readiness | Metrics, traces, audit logs, retention, backup/restore, and incident runbooks are connected to the deployment platform. |

Start only after the target identity provider, TAXII server, downstream transport, data volume, and
service-level objectives are known. Keep vendor-specific policy outside the graph domain modules.
