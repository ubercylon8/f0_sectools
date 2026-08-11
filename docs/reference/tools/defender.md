<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# `f0-defender` tool reference

Module `f0_defender_mcp.server` · **7 tools** (5 read + 2 gated write) · [server README](../../../servers/defender-mcp/README.md)

> 🔒 Gated write tools require the platform write flag **and** a per-action human confirmation — see the [security model](../../explanation/security-model.md#gated-write-actions).

## `get_secure_score`

Get the Microsoft Secure Score — Microsoft 365 / Defender config-hardening posture (%).

Microsoft tenant configuration only — not the LimaCharlie endpoint deployment
(use get_org_overview) or the ProjectAchilles validation fleet (use get_fleet_health).

*No parameters.*

Used by skills: [`roll-up-ciso-risk`](../../../skills/cross-platform/ciso-risk-rollup/SKILL.md), [`defender-posture-summary`](../../../skills/defender/posture-summary/SKILL.md), [`review-data-risk`](../../../skills/purview/data-risk-review/SKILL.md)

## `list_incidents`

List unresolved Defender XDR incidents (correlated alert groups), newest first.

severity_min: one of info|low|medium|high|critical. limit: max incidents.
Defaults to state="open" — excludes resolved incidents and ones redirected
into another incident, which Defender retains indefinitely and which are
already handled. Use state="all" for incident history.

For the Sentinel SOC queue view of the same incidents — with MITRE tactics,
SOC status and owner — use f0-sentinel's list_sentinel_incidents.

| Parameter | Type | Default |
|---|---|---|
| `severity_min` | `"info"` \| `"low"` \| `"medium"` \| `"high"` \| `"critical"` | `"medium"` |
| `limit` | `integer` | `25` |
| `state` | `"open"` \| `"all"` | `"open"` |

Used by skills: [`triage-incident-cross-platform`](../../../skills/cross-platform/triage-incident-cross-platform/SKILL.md), [`defender-posture-summary`](../../../skills/defender/posture-summary/SKILL.md), [`triage-defender-incident`](../../../skills/defender/triage-incident/SKILL.md), [`intune-device-triage`](../../../skills/intune/device-triage/SKILL.md), [`detection-coverage`](../../../skills/sentinel/detection-coverage/SKILL.md)

## `list_alerts`

List unresolved Defender XDR alerts (alerts_v2), newest first.

severity_min: one of info|low|medium|high|critical. limit: max alerts.
Defaults to state="open" — excludes resolved alerts, which are already
handled and which dominate a mature tenant. Use state="all" for alert history.

| Parameter | Type | Default |
|---|---|---|
| `severity_min` | `"info"` \| `"low"` \| `"medium"` \| `"high"` \| `"critical"` | `"high"` |
| `limit` | `integer` | `25` |
| `state` | `"open"` \| `"all"` | `"open"` |

Used by skills: [`triage-incident-cross-platform`](../../../skills/cross-platform/triage-incident-cross-platform/SKILL.md), [`triage-defender-incident`](../../../skills/defender/triage-incident/SKILL.md), [`intune-device-triage`](../../../skills/intune/device-triage/SKILL.md)

## `run_hunting_query`

Run a Microsoft Defender advanced hunting query (KQL) — a READ-ONLY search of
M365 / Entra / device telemetry (30d).

This only reads. To contain or reconnect a device use isolate_host /
release_host; this tool never changes a device's state.
For LimaCharlie endpoint (EDR sensor) telemetry, use query_telemetry instead —
this tool is Microsoft/Defender + KQL only. Construct a `kql` query string.
For common hunts prefer the `hunt` tool (it builds the KQL for you); use this
only for a CUSTOM KQL query you provide. Key tables & fields: DeviceNetworkEvents
(Timestamp, RemoteUrl, RemoteIP, RemotePort), DeviceProcessEvents (Timestamp,
DeviceName, FileName, ProcessCommandLine, AccountName), DeviceLogonEvents
(Timestamp, ActionType, AccountName, DeviceName), EmailEvents (Timestamp,
SenderFromAddress, Subject, ThreatTypes). Always bound results with `| take 50`.

This is Defender advanced hunting (device, email and identity tables), not
Sentinel workspace KQL. For firewall, DNS, syslog or other Log Analytics
tables use f0-sentinel's run_kql.

| Parameter | Type | Default |
|---|---|---|
| `kql` | `string` | *(required)* |

Used by skills: [`defender-threat-hunt`](../../../skills/defender/threat-hunt/SKILL.md)

## `hunt`

SEARCH raw Defender telemetry for suspicious activity — the server writes the KQL.

Searches the raw event tables, NOT the alerts Defender already raised (for
those use list_alerts). Choose the category by what you are looking for:
  logon   — failed sign-ins, sign-in failures, brute force, password spray
  network — traffic to a domain or IP
  process — a process name or command line
  email   — phishing or malware-bearing mail

indicator: REQUIRED for network (the domain or IP to match) and REQUIRED for
process (the process name or command-line fragment to match) — name the thing
the user asked about. Only logon and email take no indicator; they sweep on
their own. Prefer this over run_hunting_query unless the user gives you
custom KQL.

| Parameter | Type | Default |
|---|---|---|
| `category` | `"network"` \| `"process"` \| `"logon"` \| `"email"` | *(required)* |
| `indicator` | `string` | `""` |
| `time_window_hours` | `integer` | `24` |

Used by skills: [`defender-threat-hunt`](../../../skills/defender/threat-hunt/SKILL.md), [`investigate-lc-endpoint`](../../../skills/limacharlie/endpoint-investigation/SKILL.md), [`limacharlie-threat-hunt`](../../../skills/limacharlie/threat-hunt/SKILL.md), [`data-source-coverage`](../../../skills/sentinel/data-source-coverage/SKILL.md)

## `isolate_host` 🔒 *(gated write)*

CONTAIN a device: cut it off the network so it cannot communicate (GATED WRITE).

Use when asked to isolate, contain, quarantine, cut off, or take a host
offline — e.g. "isolate dev-1, I think it's compromised". This ACTS on the
device; it does not search or investigate. For telemetry use `hunt` or
`run_hunting_query`.

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

RECONNECT a device: undo isolation so it can reach the network again (GATED WRITE).

Use when asked to release, un-isolate, restore, reconnect, or take a host back
out of isolation — e.g. "release dev-1, it's been cleaned". This ACTS on the
device; it does not search or investigate.

Same two-step flow as isolate_host: call without confirmation_token to
preview, then either an operator approves it in `confirm_action.py --watch`
and you call again with the SAME arguments, or supply a token from
confirm_action.py as confirmation_token.

| Parameter | Type | Default |
|---|---|---|
| `device_id` | `string` | *(required)* |
| `comment` | `string` | *(required)* |
| `confirmation_token` | `string` | `""` |
