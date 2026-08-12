<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# `f0-sentinel` tool reference

Module `f0_sentinel_mcp.server` · **7 tools** (all read-only) · [server README](../../../servers/sentinel-mcp/README.md)

## `list_data_sources`

List which security telemetry this Sentinel workspace actually ingests.

Start here when you do not know what data exists — every workspace is
different. Returns each table with data in the last 30 days and a family
label (firewall, dns_web, office, identity, incident, custom), sorted by
ingest volume (GB, descending) and capped at `limit` (default 25) so a
large enterprise workspace doesn't flood the context. Use it to pick which
hunt tool can answer a question before you call one.

| Parameter | Type | Default |
|---|---|---|
| `limit` | `integer` | `25` |

Used by skills: [`data-source-coverage`](../../../skills/sentinel/data-source-coverage/SKILL.md), [`detection-coverage`](../../../skills/sentinel/detection-coverage/SKILL.md), [`network-investigation`](../../../skills/sentinel/network-investigation/SKILL.md)

## `hunt_firewall`

SEARCH firewall traffic (Check Point / Fortinet) for an IP or port.

Use for questions about network connections, blocked traffic, or a
suspicious IP talking through the perimeter. `indicator` must be an IP
ADDRESS or PORT NUMBER — this table carries almost no URLs or usernames, so
a domain here finds nothing: for domains, URLs and web categories use
hunt_dns_web instead. Without an indicator this returns an aggregate
(top talkers by action), not individual events.

| Parameter | Type | Default |
|---|---|---|
| `action` | `"allowed"` \| `"blocked"` \| `"detected"` \| `"any"` | `"any"` |
| `indicator` | `string` | `""` |
| `hours_back` | `number` | `24` |
| `limit` | `integer` | `25` |

Used by skills: [`network-investigation`](../../../skills/sentinel/network-investigation/SKILL.md)

## `hunt_dns_web`

SEARCH DNS, web-proxy, or remote-access VPN activity (Cisco Umbrella).

Choose surface by what you are looking for: dns — a domain was resolved or
blocked (C2, newly-registered domains, blocked categories); web — a URL was
fetched, a file downloaded, or a proxy verdict applied; vpn — remote-access
VPN sessions and failures. `indicator` is a domain, URL fragment or IP.
Without an indicator this returns an aggregate, not individual events. For
perimeter firewall connections by IP/port use hunt_firewall.

| Parameter | Type | Default |
|---|---|---|
| `surface` | `"dns"` \| `"web"` \| `"vpn"` | `"dns"` |
| `action` | `"allowed"` \| `"blocked"` \| `"detected"` \| `"any"` | `"any"` |
| `indicator` | `string` | `""` |
| `hours_back` | `number` | `24` |
| `limit` | `integer` | `25` |

Used by skills: [`network-investigation`](../../../skills/sentinel/network-investigation/SKILL.md)

## `search_office_activity`

Search Microsoft 365 audit activity: who accessed, downloaded, or shared what.

Answers "who downloaded X", "who read that mailbox", "what did this user do
in SharePoint". Call it FIRST without `operation` to get the list of
operations that actually occurred, then again with an exact operation name
(e.g. FileDownloaded, MailItemsAccessed, FileAccessed). This is the fast
path for M365 audit — prefer it over f0-purview's search_audit_log, which
submits an asynchronous query that takes 5-15 minutes to return.

| Parameter | Type | Default |
|---|---|---|
| `workload` | `"sharepoint"` \| `"onedrive"` \| `"exchange"` \| `"teams"` \| `"any"` | `"any"` |
| `operation` | `string` | `""` |
| `user` | `string` | `""` |
| `hours_back` | `number` | `24` |
| `limit` | `integer` | `25` |

Used by skills: [`investigate-audit-activity`](../../../skills/purview/audit-investigation/SKILL.md), [`network-investigation`](../../../skills/sentinel/network-investigation/SKILL.md)

## `list_sentinel_incidents`

List the Sentinel SOC incident queue with MITRE tactics, status and owner.

Use when asked about the SOC queue, incident workload, unassigned incidents,
or which ATT&CK tactics are showing up. This is the Sentinel-side view; for
the Defender XDR-native incident view (with its own alert and device
context) use f0-defender's list_incidents. Not an alert list — for
individual alerts use f0-defender's list_alerts.

| Parameter | Type | Default |
|---|---|---|
| `severity_min` | `"informational"` \| `"low"` \| `"medium"` \| `"high"` | `"low"` |
| `status` | `"new"` \| `"active"` \| `"closed"` \| `"any"` | `"any"` |
| `hours_back` | `number` | `168` |
| `limit` | `integer` | `25` |

Used by skills: [`detection-coverage`](../../../skills/sentinel/detection-coverage/SKILL.md)

## `get_detection_coverage`

Report Sentinel's analytics-rule inventory and which MITRE tactics are UNCOVERED.

Answers "what do we actually detect?", "where are our detection gaps?",
"how many analytics rules are enabled?". Reports TWO coverage numbers, never
conflated: tactics covered by ALL enabled rules (including Microsoft-managed
ones -- Fusion, MicrosoftSecurityIncidentCreation, MLBehaviorAnalytics,
ThreatIntelligence) versus tactics covered by CUSTOM (operator-authored
Scheduled/NRT) rules alone -- a workspace can show broad coverage overall
while its own rules cover almost nothing, and that gap is the point of this
tool. Disabled rules never count toward either figure. Requires the ARM
coordinates in .env.sentinel; without them it says so.

*No parameters.*

Used by skills: [`roll-up-ciso-risk`](../../../skills/cross-platform/ciso-risk-rollup/SKILL.md), [`data-source-coverage`](../../../skills/sentinel/data-source-coverage/SKILL.md), [`detection-coverage`](../../../skills/sentinel/detection-coverage/SKILL.md)

## `run_kql`

Run a CUSTOM read-only KQL query against the Sentinel Log Analytics workspace.

Use only when no guided tool fits — prefer hunt_firewall, hunt_dns_web,
search_office_activity or list_sentinel_incidents, which build correct KQL
for you. Call list_data_sources first to learn which tables exist in this
workspace. This queries the SENTINEL workspace; for Microsoft Defender
device/email advanced-hunting tables use f0-defender's run_hunting_query
instead. The query is force-bounded if it carries no `take`.

| Parameter | Type | Default |
|---|---|---|
| `kql` | `string` | *(required)* |
| `hours_back` | `number` | `24` |
| `limit` | `integer` | `25` |
