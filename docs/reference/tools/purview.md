<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# `f0-purview` tool reference

Module `f0_purview_mcp.server` · **6 tools** (all read-only) · [server README](../../../servers/purview-mcp/README.md)

## `get_dlp_summary`

Purview data-loss (DLP) alert rollup: counts by severity and status.

The data-risk posture headline — not Defender incidents (use list_incidents)
or Secure Score (use get_secure_score). hours_back may be fractional.

| Parameter | Type | Default |
|---|---|---|
| `hours_back` | `number` | `168` |

Used by skills: [`roll-up-ciso-risk`](../../../skills/cross-platform/ciso-risk-rollup/SKILL.md), [`review-data-risk`](../../../skills/purview/data-risk-review/SKILL.md), [`triage-dlp-alerts`](../../../skills/purview/dlp-alert-triage/SKILL.md)

## `list_dlp_alerts`

List recent Purview DLP alerts (data-loss policy matches), bounded.

severity_min filters to that severity and above.

| Parameter | Type | Default |
|---|---|---|
| `hours_back` | `number` | `168` |
| `severity_min` | `"low"` \| `"medium"` \| `"high"` | `"low"` |
| `limit` | `integer` | `25` |

Used by skills: [`review-data-risk`](../../../skills/purview/data-risk-review/SKILL.md), [`triage-dlp-alerts`](../../../skills/purview/dlp-alert-triage/SKILL.md)

## `list_insider_risk_alerts`

List recent Purview Insider Risk Management alerts (potential data theft,
leaks, risky departing users). Users may appear pseudonymized by design.

| Parameter | Type | Default |
|---|---|---|
| `hours_back` | `number` | `168` |
| `limit` | `integer` | `25` |

Used by skills: [`review-data-risk`](../../../skills/purview/data-risk-review/SKILL.md)

## `list_sensitivity_labels`

List the organization's Purview sensitivity labels (classification
inventory) — answers whether data classification is actually deployed.

*No parameters.*

Used by skills: [`review-data-risk`](../../../skills/purview/data-risk-review/SKILL.md)

## `search_audit_log`

Search the Microsoft 365 unified audit log: who did what, when.

Optional flat filters: activity (an EXACT operation name like "FileDeleted",
"FileDownloaded", "MailItemsAccessed" — when unsure, search once with no
activity filter and read the operation names that return) and user (a UPN).
The search is asynchronous and typically takes 5-15 MINUTES: this call polls
briefly, then returns an audit_query_id — fetch later with
get_audit_results. NEVER resubmit the same search while one is running
(identical resubmissions are deduplicated to the in-flight query).

| Parameter | Type | Default |
|---|---|---|
| `activity` | `string` | `""` |
| `user` | `string` | `""` |
| `hours_back` | `number` | `24` |
| `limit` | `integer` | `25` |

Used by skills: [`investigate-audit-activity`](../../../skills/purview/audit-investigation/SKILL.md)

## `get_audit_results`

Fetch the results of a previously submitted audit search (the
audit_query_id returned by search_audit_log when it was still running).

May pause briefly (~15s) polling the query before returning; if it is still
not ready, returns a 'still running' finding — wait a few minutes and call
this ONCE more, do not loop on it.

| Parameter | Type | Default |
|---|---|---|
| `audit_query_id` | `string` | *(required)* |
| `limit` | `integer` | `25` |

Used by skills: [`investigate-audit-activity`](../../../skills/purview/audit-investigation/SKILL.md)
