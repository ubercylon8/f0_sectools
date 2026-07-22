<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# `f0-limacharlie` tool reference

Module `f0_limacharlie_mcp.server` · **6 tools** (all read-only) · [server README](../../../servers/limacharlie-mcp/README.md)

## `get_org_overview`

LimaCharlie EDR deployment posture: sensor counts, D&R rule count, recent detection volume.

The LimaCharlie endpoint/detection deployment — not Microsoft tenant config
(use get_secure_score) or the ProjectAchilles validation fleet (use get_fleet_health).

*No parameters.*

Used by skills: [`review-detection-coverage`](../../../skills/limacharlie/detection-coverage-review/SKILL.md), [`review-data-risk`](../../../skills/purview/data-risk-review/SKILL.md)

## `list_sensors`

List LimaCharlie sensors (endpoints): hostname, platform, online status.

Set `tag` to list only sensors carrying that tag — e.g. tag="lc:sleeper" for
dormant sensors that collect no telemetry, or any operator tag.

| Parameter | Type | Default |
|---|---|---|
| `online_only` | `boolean` | `False` |
| `limit` | `integer` | `50` |
| `tag` | `string` | `""` |

Used by skills: [`investigate-lc-endpoint`](../../../skills/limacharlie/endpoint-investigation/SKILL.md)

## `get_sensor`

Get LimaCharlie sensor detail by hostname (prefix match): platform, online status, sid, tags.

Tags include lc:sleeper — a dormant sensor that collects no telemetry.

| Parameter | Type | Default |
|---|---|---|
| `hostname` | `string` | *(required)* |

Used by skills: [`triage-incident-cross-platform`](../../../skills/cross-platform/triage-incident-cross-platform/SKILL.md), [`investigate-lc-endpoint`](../../../skills/limacharlie/endpoint-investigation/SKILL.md)

## `list_dr_rules`

List Detection & Response (D&R) rules in the org (coverage). namespace: general|managed.

| Parameter | Type | Default |
|---|---|---|
| `namespace` | `string` | `"general"` |
| `limit` | `integer` | `50` |

Used by skills: [`validation-coverage-loop`](../../../skills/cross-platform/validation-coverage-loop/SKILL.md), [`review-detection-coverage`](../../../skills/limacharlie/detection-coverage-review/SKILL.md)

## `list_detections`

List recent LimaCharlie detections (D&R hits) within the last hours_back hours.

hours_back may be fractional for short windows (e.g. 0.25 = last 15 minutes).

| Parameter | Type | Default |
|---|---|---|
| `hours_back` | `number` | `24` |
| `limit` | `integer` | `50` |
| `category` | `string` \| `null` | `None` |

Used by skills: [`validation-coverage-loop`](../../../skills/cross-platform/validation-coverage-loop/SKILL.md), [`review-detection-coverage`](../../../skills/limacharlie/detection-coverage-review/SKILL.md)

## `query_telemetry`

Hunt LimaCharlie endpoint (EDR sensor) telemetry with a guided preset — no LCQL needed.

For Microsoft Defender / KQL hunts, use run_hunting_query instead — this tool
is LimaCharlie sensor telemetry only. Pick a `hunt` preset: new_processes,
powershell_activity, dns_requests, network_connections, or user_activity
("what users were seen", with the host each was seen on). hours_back bounds the
window and may be fractional (0.25 = last 15 minutes). Set `hostname` to scope to
ONE sensor (e.g. "top processes on host X") — a short name is fine; it is resolved
to the sensor's stored hostname. Set `domain` to check whether a host
resolved a domain (e.g. "does host X connect to microsoft.com") — it routes to DNS
lookups matching that domain exactly or as a subdomain (NETWORK_CONNECTIONS has IPs,
not domains; lookalikes like microsoft.com.evil.net are excluded). Set `username`
to filter process/PowerShell/user activity by the acting user (e.g. "what did
jsmith run") — bare "jsmith" or qualified "DOMAIN\jsmith"; not used for domain
lookups (DNS events carry no user).
Returns a count plus one finding per event. Advanced: pass a raw `lcql` query to
override the preset (shape: time | sensor-selector | event-types | filter | projection).

| Parameter | Type | Default |
|---|---|---|
| `hunt` | `"new_processes"` \| `"powershell_activity"` \| `"dns_requests"` \| `"network_connections"` \| `"user_activity"` | `"new_processes"` |
| `hours_back` | `number` | `24` |
| `limit` | `integer` | `50` |
| `hostname` | `string` \| `null` | `None` |
| `domain` | `string` \| `null` | `None` |
| `username` | `string` \| `null` | `None` |
| `lcql` | `string` \| `null` | `None` |

Used by skills: [`triage-incident-cross-platform`](../../../skills/cross-platform/triage-incident-cross-platform/SKILL.md), [`investigate-lc-endpoint`](../../../skills/limacharlie/endpoint-investigation/SKILL.md), [`limacharlie-threat-hunt`](../../../skills/limacharlie/threat-hunt/SKILL.md)
