"""Microsoft Sentinel read tools -> findings.

Read-only. Every API failure maps to a posture finding, never an exception.
Table and field names were validated against a live workspace on 2026-08-11;
dict access is defensive throughout because the next workspace differs.
"""
from __future__ import annotations

import json
from typing import Any, Literal

from f0_sectools_core.auth.graph import GraphError
from f0_sectools_core.paging import (
    clamp_limit,
    more_available_finding,
    truncation_finding,
)
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from . import normalize as n
from .errors import map_sentinel_error
from .probe import probed_tables, require_table

_FAMILY_PREFIX = (
    ("CommonSecurityLog", "firewall"),
    # Must come before the generic "Cisco_Umbrella" entry below: without this,
    # Cisco_Umbrella_firewall_CL matches the generic prefix and gets labelled
    # dns_web -- the family whose tool (hunt_dns_web) cannot query it, while
    # the tool that could plausibly cover it (hunt_firewall) is never
    # suggested. No hunt_* tool queries this table either way; this entry only
    # fixes the label so list_data_sources doesn't point the model at the
    # wrong hunt tool for it.
    ("Cisco_Umbrella_firewall", "firewall"),
    ("Cisco_Umbrella", "dns_web"),
    ("OfficeActivity", "office"),
    ("SecurityIncident", "incident"),
    ("SecurityAlert", "incident"),
    ("SigninLogs", "identity"),
    ("AAD", "identity"),
    ("IdentityInfo", "identity"),
    ("BehaviorAnalytics", "identity"),
    ("Syslog", "firewall"),
)


def _family(table: str) -> str:
    for prefix, fam in _FAMILY_PREFIX:
        if table.startswith(prefix):
            return fam
    return "custom"


def _bad_arg(name: str, value: str, accepted: str) -> Finding:
    """A rejected argument is reported, never silently dropped from the filter."""
    return Finding(
        source="sentinel",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Unsupported {name} '{value[:60]}'",
        recommended_action=RecommendedAction(summary=f"Accepted: {accepted}.", confidence="high"),
    )


async def _probe_or_finding(
    client: Any, table: str, human: str, cap: str, half: Literal["logs", "arm"] = "logs"
) -> Finding | None:
    """`require_table`, but inside the same GraphError handling every tool uses.

    `require_table` itself calls `probed_tables`, which issues a `client.query`
    -- a real transport call that can raise `GraphError` (403 missing role, 401
    bad creds, 429 throttled, ...) exactly like any other query. A caller that
    awaits `require_table` outside its own try/except lets that exception
    escape past `tools.py`, past `server.py`'s `_render`, and past redaction --
    the one failure mode Critical Rule 3/4 exist to prevent. Every tool that
    needs `require_table` must call it through here instead of directly.

    Returns None when the table is present (caller proceeds), or the single
    finding to return: either the "table absent" posture finding, or the
    mapped API-error finding. Re-raises only if `map_sentinel_error` does not
    recognize the error, matching every other call site in this module.
    """
    try:
        return await require_table(client, table, human)
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half=half)
        if mapped:
            return mapped
        raise


async def list_data_sources(client: Any, limit: int = 25) -> list[Finding]:
    """What telemetry this workspace actually ingests (last 30 days), by volume.

    Each table's finding carries its rounded GB and a one-word family label as
    evidence, and the list is sorted by GB descending -- a 250 GB/30d feed and a
    0.02 GB/30d trickle are very different claims about what this workspace can
    answer, so the volume figure the probe already computed is not discarded.

    Bounded to `limit` tables (default 25, clamped like every other tool):
    this is the tool every other tool's description names as the first call,
    so an unbounded dump here is a context flood on a large enterprise
    workspace. The sort is GB-descending, so the top `limit` is the useful N.
    """
    cap = "Sentinel data sources"
    try:
        table_gb = await probed_tables(client)
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not table_gb:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title="No telemetry found in this Sentinel workspace (last 30 days)",
                recommended_action=RecommendedAction(
                    summary="Check that connectors are configured and the app has "
                    "the Log Analytics Reader role.",
                ),
            )
        ]

    all_tables = sorted(table_gb, key=lambda t: table_gb[t], reverse=True)
    limit = clamp_limit(limit)
    shown = all_tables[:limit]
    findings = [
        Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"{len(all_tables)} tables ingesting in this Sentinel workspace (30d)",
            entity=Entity(kind=EntityKind.tenant, id="sentinel"),
            evidence=[Evidence(key="table_count", value=str(len(all_tables)))],
        )
    ]
    for t in shown:
        findings.append(
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"{t} — ingesting",
                entity=Entity(kind=EntityKind.tenant, id=t, name=t),
                evidence=[
                    Evidence(key="family", value=_family(t)),
                    Evidence(key="gb_30d", value=f"{table_gb[t]:.2f}"),
                ],
            )
        )
    if len(all_tables) > limit:
        findings.append(
            more_available_finding(
                "sentinel", shown=len(shown), total=len(all_tables),
                hint="Raise limit to see more tables (sorted by ingest volume, GB descending).",
            )
        )
    return findings


_INDICATOR_HELP = {
    "net": "an IP address or a port number (this table carries no URLs or "
    "usernames — for domains and URLs use hunt_dns_web)",
    "domain": "a domain, URL fragment, IP address, or an Umbrella identity "
    "(the AD user or roaming-client machine name that made the request)",
    "flow": "an IP address, a port number, or the identity (AD user) behind "
    "the flow — this table carries no usable URL, domain or country data",
}


def _expand_identities(row: dict[str, Any], spec: n.Surface) -> dict[str, Any]:
    """Replace a surface's raw identity array with flat host/user evidence keys.

    Rewritten in place of the original column so field grouping survives, and
    the classifier column is consumed rather than shown -- it exists to sort the
    identities, and echoing it back would just be another array for the reader
    to parse.
    """
    if not spec.identity_field or spec.identity_field not in row:
        return row
    host, user, other = n.split_identities(
        row.get(spec.identity_field), row.get("Identity_Types_s", "")
    )
    out: dict[str, Any] = {}
    for key, value in row.items():
        if key == spec.identity_field:
            if host:
                out["identity_host"] = host
            if user:
                out["identity_user"] = user
            if other:
                out["identity_other"] = other
        elif key != "Identity_Types_s":
            out[key] = value
    return out


def _fetch_bound(limit: int) -> int:
    """Ask the platform for one row more than we intend to show.

    `len(rows) >= limit` cannot tell "exactly limit rows exist" from "limit
    rows and more", so it reports truncation that never happened. Fetching one
    spare row turns the question into a fact for the cost of a single row.
    """
    return limit + 1


def _split_page(rows: list[dict[str, Any]], limit: int) -> tuple[list[dict[str, Any]], bool]:
    """Split a `_fetch_bound` result into the rows to show and "was there more?"."""
    return rows[:limit], len(rows) > limit


def _more(shown: int, has_more: bool, hint: str) -> list[Finding]:
    """The core truncation note, or nothing when the page was complete."""
    f = truncation_finding("sentinel", shown=shown, fetched=shown, has_more=has_more, hint=hint)
    return [f] if f else []


def _rows_to_findings(rows: list[dict[str, Any]], title_key: str, limit: int) -> list[Finding]:
    out: list[Finding] = []
    for r in rows[:limit]:
        out.append(
            Finding(
                source="sentinel",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=str(r.get(title_key) or "event"),
                evidence=[
                    Evidence(key=str(k), value=str(v))
                    for k, v in r.items()
                    if v is not None and str(v) != ""
                ][:12],
                observed_at=str(r.get("TimeGenerated") or "") or None,
            )
        )
    return out


async def _run_surface(
    client: Any,
    spec: n.Surface,
    cap: str,
    human: str,
    action: str,
    indicator: str,
    hours_back: float,
    limit: int,
) -> list[Finding]:
    """Shared execution path for every KQL telemetry surface.

    Bounding rules live here so no individual tool can forget one: time
    predicate first, retention clamp, limit clamp, and aggregate-only whenever
    no indicator narrows the scan.
    """
    if action not in n.ACTIONS:
        return [_bad_arg("action", action, ", ".join(n.ACTIONS))]
    if action != "any" and action not in spec.action_map:
        # `action` is a member of the GLOBAL vocabulary (n.ACTIONS) but this
        # surface's action_map doesn't define it -- e.g. "detected" exists for
        # hunt_firewall but not for the Umbrella surfaces. action_clause()
        # would silently no-op and return every row instead of filtering, so
        # reject it here rather than let the filter vanish unnoticed.
        accepted = "any, " + ", ".join(spec.action_map)
        return [_bad_arg("action", action, accepted)]
    if not n.validate_indicator(indicator, spec.indicator_kind):
        return [
            _bad_arg(
                "indicator", indicator,
                _INDICATOR_HELP.get(spec.indicator_kind, "a valid indicator for this surface"),
            )
        ]

    missing = await _probe_or_finding(client, spec.table, human, cap)
    if missing:
        return [missing]

    hours = n.clamp_hours(hours_back, client.retention_days)
    limit = clamp_limit(limit)

    parts = [
        spec.table,
        f"| where TimeGenerated > ago({hours:g}h)",
        n.hygiene_clause(spec),
        n.action_clause(spec, action),
        n.indicator_clause(spec, indicator),
    ]
    if indicator:
        parts.append(f"| project {', '.join(spec.project)}")
        parts.append(f"| order by TimeGenerated desc | take {_fetch_bound(limit)}")
    else:
        # No indicator -> aggregate. Never dump rows from a table this large.
        parts.append(
            f"| summarize Events=count() by {spec.action_field}, {spec.indicator_fields[0]}"
        )
        # limit + 1 here as well: `top {limit}` can never return more than
        # limit rows, so has_more was structurally always False and the
        # aggregate silently hid every group past the cut.
        parts.append(f"| top {_fetch_bound(limit)} by Events desc")
    kql = " ".join(p for p in parts if p)

    try:
        rows = await client.query(kql, n.timespan(hours))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not rows:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=f"No {human} activity matched in the last {hours:g}h",
                recommended_action=RecommendedAction(
                    summary="Widen hours, relax action, or drop the indicator.",
                ),
            )
        ]

    title_key = spec.indicator_fields[0] if indicator else spec.action_field
    shown, has_more = _split_page(rows, limit)
    shown = [_expand_identities(r, spec) for r in shown]
    findings = _rows_to_findings(shown, title_key, limit)
    return findings + _more(
        len(findings), has_more, "Narrow with an indicator or a shorter hours window."
    )


_FIREWALL_HUMAN = {
    "perimeter": "perimeter firewall (CEF)",
    "cloud": "cloud firewall (Cisco Umbrella)",
}


async def hunt_firewall(
    client: Any,
    surface: str = "perimeter",
    action: str = "any",
    indicator: str = "",
    hours_back: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """Firewall traffic: on-prem CEF appliances, or Umbrella's cloud firewall."""
    if surface not in n.FIREWALL_SURFACES:
        return [_bad_arg("surface", surface, ", ".join(n.FIREWALL_SURFACES))]
    return await _run_surface(
        client, n.SURFACE_SPECS[n.FIREWALL_SURFACES[surface]],
        cap=f"Sentinel {surface} firewall telemetry", human=_FIREWALL_HUMAN[surface],
        action=action, indicator=indicator, hours_back=hours_back, limit=limit,
    )


_SURFACE_HUMAN = {
    "dns": "DNS (Cisco Umbrella)",
    "web": "web proxy (Cisco Umbrella)",
    "vpn": "remote-access VPN (Cisco Umbrella)",
}


async def hunt_dns_web(
    client: Any,
    surface: str = "dns",
    action: str = "any",
    indicator: str = "",
    hours_back: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """DNS / web-proxy / RA-VPN activity from the Cisco Umbrella tables."""
    if surface not in n.SURFACES:
        return [_bad_arg("surface", surface, ", ".join(n.SURFACES))]
    return await _run_surface(
        client, n.SURFACE_SPECS[surface],
        cap=f"Sentinel {surface} telemetry", human=_SURFACE_HUMAN[surface],
        action=action, indicator=indicator, hours_back=hours_back, limit=limit,
    )


# Live-verified 2026-08-11: OfficeWorkload values are these exact strings.
_WORKLOAD_VALUE = {
    "sharepoint": "SharePoint",
    "onedrive": "OneDrive",
    "exchange": "Exchange",
    "teams": "MicrosoftTeams",
}
_OA_PROJECT = (
    "TimeGenerated", "OfficeWorkload", "Operation", "UserId",
    "ClientIP", "OfficeObjectId", "ResultStatus",
)


async def search_office_activity(
    client: Any,
    workload: str = "any",
    operation: str = "",
    user: str = "",
    hours_back: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """Microsoft 365 audit activity from OfficeActivity (fast path vs. Purview)."""
    cap = "Sentinel Microsoft 365 activity"
    if workload not in n.WORKLOADS:
        return [_bad_arg("workload", workload, ", ".join(n.WORKLOADS))]
    if operation and not n.WORD_RE.fullmatch(operation):
        return [_bad_arg("operation", operation, "an exact operation name, e.g. FileDownloaded")]
    if user and not n.UPN_RE.fullmatch(user):
        return [_bad_arg("user", user, "a UPN, e.g. someone@contoso.com")]

    missing = await _probe_or_finding(
        client, "OfficeActivity", "Microsoft 365 audit (OfficeActivity)", cap
    )
    if missing:
        return [missing]

    hours = n.clamp_hours(hours_back, client.retention_days)
    limit = clamp_limit(limit)

    parts = ["OfficeActivity", f"| where TimeGenerated > ago({hours:g}h)"]
    if workload != "any":
        parts.append(f'| where OfficeWorkload =~ "{_WORKLOAD_VALUE[workload]}"')
    if user:
        parts.append(f'| where UserId =~ "{user}"')
    if operation:
        parts.append(f'| where Operation =~ "{operation}"')
        parts.append(f"| project {', '.join(_OA_PROJECT)}")
        parts.append(f"| order by TimeGenerated desc | take {_fetch_bound(limit)}")
    else:
        # Discovery mode: hand back the operation vocabulary so the model can
        # pick a real value rather than inventing one.
        parts.append(
            f"| summarize Events=count() by Operation "
            f"| top {_fetch_bound(limit)} by Events desc"
        )
    kql = " ".join(parts)

    try:
        rows = await client.query(kql, n.timespan(hours))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not rows:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=f"No Microsoft 365 activity matched in the last {hours:g}h",
                recommended_action=RecommendedAction(
                    summary="Call again without `operation` to see which operations "
                    "actually occur in this window.",
                ),
            )
        ]
    shown_rows, has_more = _split_page(rows, limit)
    if not operation:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"{r.get('Operation')} — {r.get('Events')} events ({hours:g}h)",
                evidence=[
                    Evidence(key="operation", value=str(r.get("Operation"))),
                    Evidence(key="events", value=str(r.get("Events"))),
                ],
                recommended_action=RecommendedAction(
                    summary=f"Call search_office_activity with "
                    f"operation=\"{r.get('Operation')}\" to see the events.",
                ),
            )
            for r in shown_rows
        ] + _more(
            len(shown_rows), has_more,
            "Raise limit to see more operations, or pick one and call again with it.",
        )
    return _rows_to_findings(shown_rows, "Operation", limit) + _more(
        len(shown_rows), has_more, "Narrow with a shorter hours window or raise limit."
    )


_SEV_ORDER = ("informational", "low", "medium", "high")
_SEV_VALUE = {
    "informational": "Informational", "low": "Low", "medium": "Medium", "high": "High",
}
_SEV_FINDING = {
    "informational": Severity.info, "low": Severity.low,
    "medium": Severity.medium, "high": Severity.high,
}
_STATUS_VALUE = {"new": "New", "active": "Active", "closed": "Closed"}
# "open" is an exclusion, not a value: Sentinel's Status vocabulary can grow
# (an allow-list of ("New","Active") would silently drop a state added later),
# so open work is defined as "not Closed". Same reasoning as the Defender read
# tools, which prefer ne-exclusions of closed states over allow-lists.
_STATUS_CHOICES = ("open", "new", "active", "closed", "any")


def _parse_json_object(raw: Any) -> dict[str, Any]:
    """Defensively parse a Sentinel JSON-string column into a dict.

    `SecurityIncident.AdditionalData` and `.Owner` are JSON strings, but the
    field may be absent, an empty string, malformed JSON, or -- depending on
    the client -- already deserialized into a dict. None of those may raise;
    every non-dict outcome degrades to {}.
    """
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _incident_owner(raw: Any) -> str:
    """The assigned display name/UPN/email from the Owner JSON blob.

    Live shape: {"objectId":null,"email":null,"assignedTo":null,
    "userPrincipalName":null} -- all four are commonly null on an unassigned
    incident. Never emit the raw blob; fall back to the literal "unassigned".
    """
    owner = _parse_json_object(raw)
    for key in ("assignedTo", "userPrincipalName", "email"):
        val = owner.get(key)
        if val:
            return str(val)
    return "unassigned"


def _incident_tactics_techniques(raw: Any) -> tuple[str, str]:
    """(tactics, techniques) as comma-joined strings from AdditionalData.

    SecurityIncident has NO `Tactics` column -- MITRE tactics/techniques live
    inside `AdditionalData`, a JSON string shaped like
    {"tactics":["InitialAccess"],"techniques":["T1566"],...}.
    """
    data = _parse_json_object(raw)
    tactics = data.get("tactics")
    techniques = data.get("techniques")
    tactics_list = tactics if isinstance(tactics, list) else []
    techniques_list = techniques if isinstance(techniques, list) else []
    return (
        ", ".join(str(t) for t in tactics_list),
        ", ".join(str(t) for t in techniques_list),
    )


async def list_sentinel_incidents(
    client: Any,
    severity_min: str = "low",
    status: str = "open",
    hours_back: float = 168,
    limit: int = 25,
) -> list[Finding]:
    """The Sentinel SOC incident queue, with MITRE tactics."""
    cap = "Sentinel incidents"
    if severity_min not in _SEV_ORDER:
        return [_bad_arg("severity_min", severity_min, ", ".join(_SEV_ORDER))]
    if status not in _STATUS_CHOICES:
        return [_bad_arg("status", status, ", ".join(_STATUS_CHOICES))]

    missing = await _probe_or_finding(client, "SecurityIncident", "Sentinel incidents", cap)
    if missing:
        return [missing]

    hours = n.clamp_hours(hours_back, client.retention_days)
    limit = clamp_limit(limit)
    wanted = _SEV_ORDER[_SEV_ORDER.index(severity_min):]
    sev_list = ", ".join(f'"{_SEV_VALUE[s]}"' for s in wanted)

    parts = [
        "SecurityIncident",
        f"| where TimeGenerated > ago({hours:g}h)",
        # SecurityIncident appends a row per update; collapse to the latest
        # state per incident or the queue reads as duplicates.
        "| summarize arg_max(TimeGenerated, *) by IncidentNumber",
        f"| where Severity in~ ({sev_list})",
    ]
    if status == "open":
        parts.append('| where Status !~ "Closed"')
    elif status != "any":
        parts.append(f'| where Status =~ "{_STATUS_VALUE[status]}"')
    parts.append("| order by TimeGenerated desc")
    parts.append(f"| take {_fetch_bound(limit)}")
    kql = " ".join(parts)

    try:
        rows = await client.query(kql, n.timespan(hours))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not rows:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=(
                    f"No {'open ' if status == 'open' else ''}Sentinel incidents at "
                    f"severity {severity_min}+ in the last {hours:g}h"
                ),
            )
        ]

    shown_rows, has_more = _split_page(rows, limit)
    out: list[Finding] = []
    for r in shown_rows:
        num = str(r.get("IncidentNumber", "?"))
        tactics, techniques = _incident_tactics_techniques(r.get("AdditionalData"))
        out.append(
            Finding(
                source="sentinel",
                finding_type=FindingType.incident,
                severity=_SEV_FINDING.get(str(r.get("Severity", "")).lower(), Severity.medium),
                title=f"#{num}: {r.get('Title') or 'Sentinel incident'}",
                entity=Entity(kind=EntityKind.tenant, id=num, name=str(r.get("Title") or "")),
                evidence=[
                    Evidence(key="status", value=str(r.get("Status") or "")),
                    Evidence(key="severity", value=str(r.get("Severity") or "")),
                    Evidence(key="tactics", value=tactics),
                    Evidence(key="techniques", value=techniques),
                    Evidence(key="owner", value=_incident_owner(r.get("Owner"))),
                ],
                observed_at=str(r.get("TimeGenerated") or "") or None,
            )
        )
    return out + _more(
        len(out), has_more, "Raise limit, shorten hours_back, or filter with severity_min."
    )


# The MITRE tactics Sentinel analytics rules can carry. Used to name the GAP —
# a rule inventory without the uncovered set is just a count.
_ALL_TACTICS = (
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact",
)


# Analytics-rule `kind` values that are Microsoft-managed, not operator-
# authored. `Scheduled` and `NRT` are the genuinely custom kinds -- the
# operator wrote the KQL and picked the tactics. Everything below generates
# or imports alerts through Microsoft's own logic instead:
_BUILTIN_RULE_KINDS = frozenset({
    "Fusion",                             # built-in multistage-attack correlation
    "MicrosoftSecurityIncidentCreation",  # imports Defender/MCAS alerts as incidents
    "MLBehaviorAnalytics",                # built-in ML/UEBA anomaly rules
    "ThreatIntelligence",                 # built-in TI-indicator matching rules
})
# ARM `name` conventionally used for the built-in Fusion rule -- a
# live-observed belt-and-suspenders alongside `kind` in case a workspace ever
# renames or re-kinds it.
_BUILTIN_RULE_NAMES = frozenset({"BuiltInFusion"})


def _is_builtin_rule(r: dict[str, Any]) -> bool:
    """True for a Microsoft-managed rule kind, not an operator-authored one.

    Counting a Microsoft-managed rule's tactics as "custom" coverage
    overstates what the operator actually built -- the same defect this
    function exists to prevent for Fusion specifically. When Microsoft ships
    another built-in kind, add it to `_BUILTIN_RULE_KINDS` (a one-line data
    change) rather than re-deriving this classification.
    """
    return (
        str(r.get("kind", "")) in _BUILTIN_RULE_KINDS
        or str(r.get("name", "")) in _BUILTIN_RULE_NAMES
    )


# Below this many custom-covered tactics an operator has less than a third of
# the ATT&CK matrix (14 tactics) covered by rules they actually authored --
# worth flagging at medium severity rather than the default info, regardless
# of how many built-in rules are also enabled.
_LOW_CUSTOM_COVERAGE_THRESHOLD = 4

# Per-rule findings are capped so an enterprise tenant with hundreds of
# enabled rules doesn't dump them all -- the summary finding above already
# carries the aggregate counts and tactic sets; these per-rule findings are
# supplementary detail, not the coverage answer itself.
_MAX_RULE_FINDINGS = 25


async def get_detection_coverage(client: Any) -> list[Finding]:
    """Analytics-rule inventory and MITRE tactic gaps, built-in vs custom.

    Reports two coverage numbers, never conflated: the tactic set covered by
    ALL enabled rules (including Microsoft-managed ones -- see
    `_BUILTIN_RULE_KINDS`: Fusion, MicrosoftSecurityIncidentCreation,
    MLBehaviorAnalytics, ThreatIntelligence) and the tactic set covered by
    CUSTOM (operator-authored `Scheduled`/`NRT`) rules alone. Only enabled
    rules count toward either figure -- a disabled rule detects nothing. A
    workspace can show "12 of 14 tactics covered" overall while its own
    analytics rules cover only 2 -- the rest comes from Microsoft's own rules,
    not from anything the operator built. Collapsing those into one number
    hides the actual detection gap this tool exists to name.
    """
    cap = "Sentinel detection coverage"
    if not client.has_arm:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title="Sentinel detection coverage unavailable — ARM coordinates not configured",
                recommended_action=RecommendedAction(
                    summary="Set SENTINEL_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP and "
                    "SENTINEL_WORKSPACE_NAME in .env.sentinel, and grant the app the "
                    "'Microsoft Sentinel Reader' role.",
                    confidence="high",
                ),
            )
        ]

    try:
        rules = await client.arm_list("alertRules")
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="arm")
        if mapped:
            return [mapped]
        raise

    enabled = [r for r in rules if (r.get("properties") or {}).get("enabled")]
    custom_rules = [r for r in rules if not _is_builtin_rule(r)]
    # `kinds` is a pure inventory breakdown (informational), so it counts
    # every rule regardless of enabled state.
    kinds: dict[str, int] = {}
    for r in rules:
        kind = str(r.get("kind", "unknown"))
        kinds[kind] = kinds.get(kind, 0) + 1

    # Coverage, by contrast, is a claim about what actually detects
    # something today -- a disabled rule detects nothing, so its tactics
    # must never count as covered. Aggregate from `enabled` only.
    covered_all: set[str] = set()
    covered_custom: set[str] = set()
    for r in enabled:
        tactics = (r.get("properties") or {}).get("tactics") or []
        is_builtin = _is_builtin_rule(r)
        for t in tactics:
            covered_all.add(str(t))
            if not is_builtin:
                covered_custom.add(str(t))
    uncovered_all = [t for t in _ALL_TACTICS if t not in covered_all]
    uncovered_custom = [t for t in _ALL_TACTICS if t not in covered_custom]

    custom_tactics_str = ", ".join(sorted(covered_custom)) or "none"
    uncovered_custom_str = ", ".join(uncovered_custom) or "none"

    summary = Finding(
        source="sentinel",
        finding_type=FindingType.posture,
        severity=Severity.medium if len(covered_custom) < _LOW_CUSTOM_COVERAGE_THRESHOLD
        else Severity.info,
        title=f"{len(rules)} Sentinel analytics rules ({len(enabled)} enabled, "
        f"{len(custom_rules)} custom) — {len(covered_custom)} of {len(_ALL_TACTICS)} "
        f"MITRE tactics covered by custom rules ({len(covered_all)} covered overall, "
        "incl. Microsoft-managed rules)",
        entity=Entity(kind=EntityKind.tenant, id="sentinel"),
        evidence=[
            Evidence(key="rules_total", value=str(len(rules))),
            Evidence(key="rules_enabled", value=str(len(enabled))),
            Evidence(key="rules_custom", value=str(len(custom_rules))),
            Evidence(key="kinds", value=", ".join(f"{k}={v}" for k, v in sorted(kinds.items()))),
            Evidence(key="tactics_covered_all", value=", ".join(sorted(covered_all)) or "none"),
            Evidence(key="tactics_covered_custom", value=custom_tactics_str),
            Evidence(key="tactics_uncovered_all", value=", ".join(uncovered_all) or "none"),
            Evidence(key="tactics_uncovered_custom", value=uncovered_custom_str),
        ],
        recommended_action=RecommendedAction(
            summary=f"Custom (operator-authored) rules cover only "
            f"{len(covered_custom)} of {len(_ALL_TACTICS)} tactics ({custom_tactics_str}); "
            "the rest of the overall figure comes from Microsoft-managed rules (Fusion "
            f"and/or its other built-in kinds), not anything built here. Tactics "
            f"uncovered by custom rules: {uncovered_custom_str}. Add analytics rules or "
            "enable Content Hub solutions for these.",
            confidence="medium",
        ),
    )

    out = [summary]
    shown_rules = enabled[:_MAX_RULE_FINDINGS]
    for r in shown_rules:
        p = r.get("properties") or {}
        out.append(
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Rule: {p.get('displayName') or 'unnamed'}",
                entity=Entity(kind=EntityKind.rule, id=str(r.get("name") or "")),
                evidence=[
                    Evidence(key="kind", value=str(r.get("kind") or "")),
                    Evidence(key="severity", value=str(p.get("severity") or "")),
                    Evidence(
                        key="tactics",
                        value=", ".join(str(t) for t in (p.get("tactics") or [])),
                    ),
                ],
            )
        )
    if len(enabled) > _MAX_RULE_FINDINGS:
        out.append(
            more_available_finding(
                "sentinel", shown=len(shown_rules), total=len(enabled),
                hint="The summary finding above already carries the full aggregate "
                "counts and tactic sets; these are per-rule detail only.",
            )
        )
    return out


# Kusto control commands start with a dot and can mutate the workspace
# (.create, .drop, .set-or-append, .ingest). This server is read-only, so they
# never reach the API. The guard below checks every LINE, not just the whole
# query: "print 1\n.show diagnostics" is a single query string but the second
# line is a control command, and the Log Analytics /v1/.../query endpoint
# ultimately decides what a raw string does, not us -- reject before dispatch,
# don't rely on the endpoint being query-only today.
#
# EVERY LINE IS CLASSIFIED AT FACE VALUE. There is no verbatim-string
# exemption, and none should be re-added. A previous version tried to skip
# lines that a caller-controlled ``` fence count claimed were inside a
# multi-line Kusto verbatim string literal, so genuine interior content
# (e.g. an embedded multi-line sample log) wouldn't be misread as a control
# command. That exemption was calculated from `query.count("```") % 2`, a
# value the caller fully controls, and it activated over lines the caller
# also fully controls -- so it was possible to hide a real control command
# behind a fence that only *looks* like a verbatim string to this guard
# (inside a `//` comment, inside a quoted string literal, or simply an
# unbalanced fence) while it stays inert to the actual Kusto engine. Real
# bypasses confirmed under that scheme included a fence inside a `//`
# comment, a fence inside a `"..."` string literal, and a fence trailing a
# same-line comment -- three different ways to toggle the guard's state
# without toggling the engine's. A partial lexer here can only ever
# SUBTRACT text from the check (mark more of the query as exempt); it has no
# way to make the guard stricter, only blinder. Properly fixing it means
# tracking comments, quoted strings and fences together -- a real KQL lexer,
# far beyond what this guard is worth. So the exemption is gone, deliberately,
# and every line -- fenced or not -- is classified as-is.
#
# The cost of that is one narrow, accepted false rejection: a query that
# embeds a multi-line verbatim string whose interior line happens to open
# with a dot-letter sequence (e.g. a sample log line starting ".example")
# now gets rejected as a control command even though it's legal KQL. See
# `test_run_kql_dot_line_inside_verbatim_string_now_rejected`. That trade is
# intentional -- this guard prefers refusing an exotic-but-legal query over
# ever dispatching a control command -- and is a strictly better trade than
# the fence machinery's failure mode, which was dispatching a real one.
#
# A line only counts as a control command when it opens with a dot and the
# first subsequent non-digit character (skipping any whitespace or other
# invisible characters in between) is a letter (.drop, .show,
# .set-or-append, . drop, .\tdrop, ...) -- every real Kusto control command
# has that shape, and Kusto's own parser tolerates the whitespace variants.
# A dot followed by a digit is a decimal literal, not a command: KQL is
# whitespace-insensitive across an unterminated expression, so a decimal
# literal opening a continuation line (`| where Ratio >` then `    .5`) is
# legal KQL and must still dispatch.
#
# Deliberately NOT rejecting ";": the same-line form
# (`Heartbeat | take 1; .drop table X`) stays open. Rejecting ";" outright
# would break legitimate KQL -- `let` statements are semicolon-separated --
# and a same-line dot-command after ";" is a narrower, harder problem than
# this fix. Documented here so the next reader doesn't mistake the gap for
# an oversight.
_CONTROL_PREFIX = "."


def _line_control_command_reason(line: str) -> Literal["ok", "nonprintable", "control"]:
    """Classify one line of a query for the control-command guard below.

    "nonprintable": `line`, once stripped, opens with an invisible/control
    character that could be hiding a dot control-command from the literal
    `.` check. Whitelist, not blacklist: str.strip() only removes ordinary
    whitespace, so a leading BOM/zero-width-space/C0/C1 control survives it.
    Rather than enumerate every Unicode category that can do this, treat a
    line that doesn't open with an ordinary printable character as unsafe by
    construction -- no legitimate KQL line starts with one.

    "control": `line`, once stripped, opens with a dot, and the first
    subsequent character that is not a digit and not whitespace/invisible is
    a letter -- e.g. `.drop`, `.show`, `. drop`, `.\tset-or-append`. Any
    whitespace or other invisible characters between the dot and the letter
    are skipped, not treated as disqualifying, because Kusto's own control
    command parser tolerates them too -- a naive "immediately followed by a
    letter" check is bypassable with a single space or zero-width character.
    A dot followed by a digit (skipping nothing) is a decimal literal, e.g.
    the ".5" in a continuation line after `| where Ratio >`, and is never a
    command.

    "ok": neither -- includes blank lines, a bare ".", ".." and similar.

    The caller applies this per line (not just to the whole query) so the
    hardening covers a dot-command hidden on any line, not only the first.
    """
    stripped = line.strip()
    if not stripped:
        return "ok"
    if not stripped[0].isprintable():
        return "nonprintable"
    if stripped[0] != _CONTROL_PREFIX:
        return "ok"
    for ch in stripped[1:]:
        if ch.isdigit():
            return "ok"  # decimal literal, e.g. ".5", ".5e3"
        if ch.isspace() or not ch.isprintable():
            continue  # whitespace/invisible characters between "." and the name
        return "control" if ch.isalpha() else "ok"
    return "ok"  # a bare ".", ".." or "." followed only by whitespace


def _nonprintable_prefix_finding() -> Finding:
    return Finding(
        source="sentinel",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title="Query must begin with ordinary text — leading invisible or "
        "control characters are not permitted",
        recommended_action=RecommendedAction(
            summary="Remove any leading invisible/control characters and "
            "retry with a plain KQL query (TableName | where ... | take N).",
            confidence="high",
        ),
    )


def _control_command_finding() -> Finding:
    return Finding(
        source="sentinel",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title="Kusto control commands are not permitted — this server is read-only",
        recommended_action=RecommendedAction(
            summary="Use a tabular query (TableName | where ... | take N).",
            confidence="high",
        ),
    )


async def run_kql(
    client: Any, kql: str, hours_back: float = 24, limit: int = 25
) -> list[Finding]:
    """Run a caller-supplied read-only KQL query, force-bounded."""
    cap = "Sentinel KQL query"
    query = (kql or "").strip()
    if not query:
        return [_bad_arg("kql", kql or "", "a KQL query, e.g. 'Heartbeat | take 10'")]
    # Every line is classified at face value -- see the comment block above
    # `_line_control_command_reason` for why there is no verbatim-string
    # exemption here (and why one must not be re-added).
    for line in query.splitlines():
        reason = _line_control_command_reason(line)
        if reason == "nonprintable":
            return [_nonprintable_prefix_finding()]
        if reason == "control":
            return [_control_command_finding()]

    hours = n.clamp_hours(hours_back, client.retention_days)
    limit = clamp_limit(limit)
    lowered = query.lower()
    if " take " not in lowered and " limit " not in lowered and not lowered.endswith("take"):
        # A new line, not a trailing " | take N" appended to the same line:
        # model-written KQL carries trailing `//` line comments routinely, and
        # `"Heartbeat // note" + " | take 25"` becomes `"Heartbeat // note |
        # take 25"` -- the whole bound silently swallowed by the comment, so
        # the query dispatches unbounded. A KQL line comment only extends to
        # the end of its own line, so a bound on the NEXT line always applies.
        query = f"{query}\n| take {_fetch_bound(limit)}"
        bounded = True
    else:
        # The caller supplied their own bound; we cannot tell a complete result
        # from a truncated one, so we must not claim either way.
        bounded = False

    try:
        rows = await client.query(query, n.timespan(hours))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not rows:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=f"Query returned no rows in the last {hours:g}h",
            )
        ]
    shown, has_more = _split_page(rows, limit) if bounded else (rows[:limit], False)
    first_col = next(iter(shown[0].keys()), "result")
    return _rows_to_findings(shown, first_col, limit) + _more(
        len(shown), has_more, "Add a filter to the query or raise limit."
    )
