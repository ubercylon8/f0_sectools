<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# `f0-defender` tool reference

Module `f0_defender_mcp.server` · **7 tools** (5 read + 2 gated write) · [server README](../../../servers/defender-mcp/README.md)

> 🔒 Gated write tools require the platform write flag **and** a per-action human confirmation — see the [security model](../../explanation/security-model.md#gated-write-actions).

## `get_secure_score`

Get the Microsoft Secure Score — Microsoft 365 / Defender config-hardening posture (%).

Microsoft tenant configuration only — not the LimaCharlie endpoint deployment
(use get_org_overview) or the ProjectAchilles validation fleet (use get_fleet_health).

*No parameters.*

Used by skills: [`defender-posture-summary`](../../../skills/defender/posture-summary/SKILL.md), [`review-data-risk`](../../../skills/purview/data-risk-review/SKILL.md)

## `list_incidents`

List Defender XDR incidents (correlated alert groups).

severity_min: one of info|low|medium|high|critical. limit: max incidents.

| Parameter | Type | Default |
|---|---|---|
| `severity_min` | `"info"` \| `"low"` \| `"medium"` \| `"high"` \| `"critical"` | `"medium"` |
| `limit` | `integer` | `25` |

Used by skills: [`triage-incident-cross-platform`](../../../skills/cross-platform/triage-incident-cross-platform/SKILL.md), [`defender-posture-summary`](../../../skills/defender/posture-summary/SKILL.md), [`triage-defender-incident`](../../../skills/defender/triage-incident/SKILL.md), [`intune-device-triage`](../../../skills/intune/device-triage/SKILL.md)

## `list_alerts`

List Defender XDR alerts (alerts_v2).

severity_min: one of info|low|medium|high|critical. limit: max alerts.

| Parameter | Type | Default |
|---|---|---|
| `severity_min` | `"info"` \| `"low"` \| `"medium"` \| `"high"` \| `"critical"` | `"high"` |
| `limit` | `integer` | `25` |

Used by skills: [`triage-incident-cross-platform`](../../../skills/cross-platform/triage-incident-cross-platform/SKILL.md), [`triage-defender-incident`](../../../skills/defender/triage-incident/SKILL.md), [`intune-device-triage`](../../../skills/intune/device-triage/SKILL.md)

## `run_hunting_query`

Run a Microsoft Defender advanced hunting query (KQL) over M365 / Entra / devices (30d).

For LimaCharlie endpoint (EDR sensor) telemetry, use query_telemetry instead —
this tool is Microsoft/Defender + KQL only. Construct a `kql` query string.
For common hunts prefer the `hunt` tool (it builds the KQL for you); use this
only for a CUSTOM KQL query you provide. Key tables & fields: DeviceNetworkEvents
(Timestamp, RemoteUrl, RemoteIP, RemotePort), DeviceProcessEvents (Timestamp,
DeviceName, FileName, ProcessCommandLine, AccountName), DeviceLogonEvents
(Timestamp, ActionType, AccountName, DeviceName), EmailEvents (Timestamp,
SenderFromAddress, Subject, ThreatTypes). Always bound results with `| take 50`.

| Parameter | Type | Default |
|---|---|---|
| `kql` | `string` | *(required)* |

Used by skills: [`defender-threat-hunt`](../../../skills/defender/threat-hunt/SKILL.md)

## `hunt`

Guided Microsoft Defender hunt — the server builds correct KQL, so you don't have to.

category: network | process | logon | email.
indicator: what to look for — a domain/IP (network), a process name or
command-line fragment (process); optional for logon/email. Prefer this over
run_hunting_query unless the user gives you custom KQL.

| Parameter | Type | Default |
|---|---|---|
| `category` | `"network"` \| `"process"` \| `"logon"` \| `"email"` | *(required)* |
| `indicator` | `string` | `""` |
| `time_window_hours` | `integer` | `24` |

Used by skills: [`defender-threat-hunt`](../../../skills/defender/threat-hunt/SKILL.md), [`investigate-lc-endpoint`](../../../skills/limacharlie/endpoint-investigation/SKILL.md), [`limacharlie-threat-hunt`](../../../skills/limacharlie/threat-hunt/SKILL.md)

## `isolate_host` 🔒 *(gated write)*

Isolate a device from the network (GATED WRITE).

Call WITHOUT confirmation_token first: returns the intended action only. An
operator then approves it in `confirm_action.py --watch` and you call again
with the SAME arguments — or supplies a token from confirm_action.py as
confirmation_token. Requires DEFENDER_ALLOW_WRITE=true.

| Parameter | Type | Default |
|---|---|---|
| `device_id` | `string` | *(required)* |
| `comment` | `string` | *(required)* |
| `confirmation_token` | `string` | `""` |

Used by skills: [`triage-incident-cross-platform`](../../../skills/cross-platform/triage-incident-cross-platform/SKILL.md)

## `release_host` 🔒 *(gated write)*

Release a device from isolation (GATED WRITE).

Same two-step flow as isolate_host: call without confirmation_token to
preview, then either an operator approves it in `confirm_action.py --watch`
and you call again with the SAME arguments, or supply a token from
confirm_action.py as confirmation_token.

| Parameter | Type | Default |
|---|---|---|
| `device_id` | `string` | *(required)* |
| `comment` | `string` | *(required)* |
| `confirmation_token` | `string` | `""` |
