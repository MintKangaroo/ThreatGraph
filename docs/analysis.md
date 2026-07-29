# Correlation and grounded narratives

ThreatGraph correlation is deterministic and bounded. It does not infer facts that are absent from
the workspace graph.

## Correlation rules

| Rule | Trigger | Finding |
| --- | --- | --- |
| Shared indicator | Two or more entities connect through the same IP, domain, URL, hash, or file | `shared_indicator` |
| Shared context | Two or more entities connect through the same asset or identity | `shared_context` |
| ATT&CK chain | An Incident connects to at least two `AttackTechnique` entities | `technique_chain` |

Only relationships intersecting the selected timezone-aware window are considered. The API limits
the window to 30 days and the input page to 200 entities. Finding UUIDs are derived from workspace,
rule, pivot, and relationship IDs, so replaying unchanged facts yields the same result.

Severity is rule-based:

- Critical: confidence at least 0.90 across four or more entities.
- High: confidence at least 0.75.
- Medium: every remaining valid finding.

## Grounding contract

Each narrative claim is generated from an actual relationship and includes:

- the supporting relationship UUID;
- the supporting Evidence UUID;
- confidence in the inclusive range 0–1.

Missing relationships or endpoints are listed in `gaps`; low overall confidence adds an analyst
review gap. A narrative is `grounded` only when it has at least one verified claim and no gap.
This guarantees that the dashboard and downstream exports can distinguish a supported statement
from an incomplete explanation.
