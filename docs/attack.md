# MITRE ATT&CK mapping

ThreatGraph represents ATT&CK techniques and sub-techniques as `AttackTechnique` entities with a
canonical external ID.

## Canonical identity

- Technique: `T####`
- Sub-technique: `T####.###`
- Graph key: the uppercase external ID
- Graph UUID: deterministic UUIDv5 derived from the external ID

An official STIX `attack-pattern` uses the MITRE external reference when available. Objects without
a valid ATT&CK external ID fall back to the general STIX mapping, so a malformed vendor extension
cannot silently become a canonical technique.

Mapped metadata includes the STIX ID, description, kill-chain tactic names, `x_mitre_platforms`,
`x_mitre_version`, `revoked`, and `x_mitre_deprecated`. Custom ATT&CK properties are accepted at the
STIX parsing boundary and normalized before entering the strict graph schema.

## Sigma tags

`sigma_attack_ids()` recognizes case-insensitive tags such as:

```text
attack.t1059
attack.t1059.001
```

It ignores malformed and non-ATT&CK tags, removes duplicates, and returns stable sorted IDs.
`sigma_technique_entities()` builds the canonical entities, while
`sigma_technique_relationships()` creates evidence-backed `uses_technique` relationships from an
Incident. The caller must supply an Evidence ID in the same workspace.

This keeps STIX knowledge imports and Sigma detections on the same graph identity.
