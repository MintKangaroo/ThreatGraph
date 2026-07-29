# Threat Intelligence Graph Schema

## Entity labels

Every node has the base `Entity` label plus exactly one domain label.

| Domain label | Purpose |
| --- | --- |
| `Asset` | Hosts, endpoints, servers, cloud resources, and network devices |
| `Identity` | Users, service accounts, and machine identities |
| `Process` | Observed process instances or stable process identities |
| `File` | Files and artifacts independent of their hashes |
| `Domain` | DNS names |
| `IPAddress` | IPv4 and IPv6 addresses |
| `URL` | Network resource locators |
| `Hash` | File or artifact digest identities |
| `Vulnerability` | CVEs and other vulnerability records |
| `Alert` | Individual security detections |
| `Incident` | Correlated investigation units |
| `ThreatActor` | Named or tracked adversaries |
| `Malware` | Malware families and specimens |
| `Campaign` | Coordinated threat activity |
| `AttackTechnique` | MITRE ATT&CK techniques and sub-techniques |
| `DataSource` | Producers of graph observations |
| `Evidence` | Immutable references supporting graph relationships |

All nodes store `id`, `workspace_id`, `identity_key`, `entity_type`, `key`, `sensitive`,
`created_at`, and `updated_at`. A uniqueness constraint on `(workspace_id, identity_key)` makes
entity upserts idempotent. The identity key is type-qualified; IOC-specific canonicalization is
added by the normalization milestone.

## Relationship types

Neo4j stores relationship labels in uppercase while domain values remain lowercase.

| Domain value | Neo4j type |
| --- | --- |
| `communicates_with` | `COMMUNICATES_WITH` |
| `resolves_to` | `RESOLVES_TO` |
| `downloaded` | `DOWNLOADED` |
| `executed` | `EXECUTED` |
| `observed_on` | `OBSERVED_ON` |
| `authenticated_to` | `AUTHENTICATED_TO` |
| `exploited` | `EXPLOITED` |
| `related_to` | `RELATED_TO` |
| `attributed_to` | `ATTRIBUTED_TO` |
| `uses_technique` | `USES_TECHNIQUE` |
| `affected_by` | `AFFECTED_BY` |
| `mitigated_by` | `MITIGATED_BY` |
| `part_of_incident` | `PART_OF_INCIDENT` |

Every relationship stores `id`, `workspace_id`, `relationship_type`, `source_entity_id`,
`target_entity_id`, `source`, `first_seen`, `last_seen`, `confidence`, `evidence_id`, `created_at`,
and `updated_at`. Confidence is constrained to the inclusive range 0–1, and `last_seen` cannot
precede `first_seen`.

## Integrity rules

1. Repository callers provide a workspace UUID on every operation.
2. Entity reads match both `workspace_id` and entity `id`.
3. Relationship writes match source, target, and `Evidence` nodes by the same `workspace_id`.
4. A missing endpoint or Evidence node fails the complete relationship transaction.
5. Arbitrary properties cannot override reserved identity, workspace, evidence, or time fields.
6. Schema installation uses only `IF NOT EXISTS` constraints and indexes and is safe to repeat.

Run `threatgraph-schema` or `make graph-schema` to install the schema manually. Docker Compose
runs the same installer through `graph-init` before starting API and worker processes.
