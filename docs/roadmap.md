# Roadmap

1. **Platform foundation (complete):** FastAPI, PostgreSQL, Neo4j, Redis/Celery, React, Compose, and
   health checks.
2. **Graph schema and repositories (complete):** typed entities, evidence-backed edges, constraints,
   indexes, idempotent upserts, and workspace isolation.
3. **STIX 2.1 (complete):** bundle import/export, workspace-scoped preservation, supported object
   mapping, relationship evidence, and TAXII adapter boundary.
4. **IOC pipeline (complete):** normalization, stable identity keys, deduplication, and optional masking.
5. **MITRE ATT&CK (next):** knowledge import and technique mapping, including Sigma mapping adapters.
6. **Correlation:** time windows, common IOC/asset/identity, and technique-chain correlation.
7. **Graph query API (in progress):** bounded workspace subgraph pagination and sensitive entity
   masking are complete; neighborhood, shortest path, and time-range queries remain.
8. **Visualization (in progress):** interactive explorer, search, filters, critical path, time
   slider, evidence panel, JSON export, and live/demo data modes are complete; server-side graph
   expansion remains.
9. **Grounded narratives:** incident and ATT&CK-chain explanations with explicit missing evidence.
10. **Platform adapters:** AI-SOC Dashboard, AutoPentest AI, and SentinelFlow integrations.

Each milestone must remain independently testable and is committed separately.
