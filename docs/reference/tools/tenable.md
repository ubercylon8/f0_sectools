<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# `f0-tenable` tool reference

Module `f0_tenable_mcp.server` · **7 tools** (all read-only) · [server README](../../../servers/tenable-mcp/README.md)

## `get_vulnerability_summary`

Tenable environment-wide vulnerability posture — counts by severity.

Use for "what's our exposure / overall vulnerability posture" questions.
Returns one posture finding with per-severity instance counts.

*No parameters.*

Used by skills: [`roll-up-ciso-risk`](../../../skills/cross-platform/ciso-risk-rollup/SKILL.md), [`review-exposure-posture`](../../../skills/tenable/exposure-posture-review/SKILL.md)

## `list_top_vulnerabilities`

Tenable worst vulnerabilities to fix first — ranked by severity then VPR.

severity_min: low|medium|high|critical (default high). Use for
"what should we patch first / top risks" questions.

| Parameter | Type | Default |
|---|---|---|
| `severity_min` | `"low"` \| `"medium"` \| `"high"` \| `"critical"` | `"high"` |
| `limit` | `integer` | `10` |

Used by skills: [`review-exposure-posture`](../../../skills/tenable/exposure-posture-review/SKILL.md), [`triage-host-vulnerabilities`](../../../skills/tenable/host-vulnerability-triage/SKILL.md)

## `list_assets`

Tenable asset inventory — hosts Tenable has scanned.

Optional hostname substring filter. Use to find or enumerate assets; for a
specific host's vulnerabilities use get_asset_vulnerabilities.

| Parameter | Type | Default |
|---|---|---|
| `hostname` | `string` | `""` |
| `limit` | `integer` | `25` |

Used by skills: [`triage-host-vulnerabilities`](../../../skills/tenable/host-vulnerability-triage/SKILL.md), [`review-scan-coverage`](../../../skills/tenable/scan-coverage-review/SKILL.md)

## `get_asset_vulnerabilities`

Tenable vulnerabilities on ONE host. `asset` is a hostname, IP, or asset UUID.

Use for "what's wrong with host X / vulnerabilities on X". severity_min:
low|medium|high|critical (default high).

| Parameter | Type | Default |
|---|---|---|
| `asset` | `string` | *(required)* |
| `severity_min` | `"low"` \| `"medium"` \| `"high"` \| `"critical"` | `"high"` |
| `limit` | `integer` | `25` |

Used by skills: [`triage-host-vulnerabilities`](../../../skills/tenable/host-vulnerability-triage/SKILL.md)

## `get_vulnerability_info`

Tenable detail for one plugin/vulnerability: CVSS, VPR, description, remediation.

Use to explain a specific Tenable plugin id or get its fix.

| Parameter | Type | Default |
|---|---|---|
| `plugin_id` | `string` | *(required)* |

Used by skills: [`triage-host-vulnerabilities`](../../../skills/tenable/host-vulnerability-triage/SKILL.md)

## `list_vulnerability_assets`

List the hosts affected by a specific Tenable vulnerability (plugin_id).

Use after list_top_vulnerabilities to see WHICH assets carry a finding.

| Parameter | Type | Default |
|---|---|---|
| `plugin_id` | `string` | *(required)* |
| `limit` | `integer` | `25` |

Used by skills: [`triage-host-vulnerabilities`](../../../skills/tenable/host-vulnerability-triage/SKILL.md)

## `list_scans`

Tenable scan inventory — each scan's status and last-run time (coverage freshness).

| Parameter | Type | Default |
|---|---|---|
| `limit` | `integer` | `25` |

Used by skills: [`review-exposure-posture`](../../../skills/tenable/exposure-posture-review/SKILL.md), [`review-scan-coverage`](../../../skills/tenable/scan-coverage-review/SKILL.md)
