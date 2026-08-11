"""Microsoft Sentinel read tools -> findings.

Read-only. Every API failure maps to a posture finding, never an exception.
Table and field names were validated against a live workspace on 2026-08-11;
dict access is defensive throughout because the next workspace differs.
"""
from __future__ import annotations

import json
from typing import Any

from f0_sectools_core.auth.graph import GraphError
from f0_sectools_core.paging import clamp_limit, more_available_finding
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


async def list_data_sources(client: Any) -> list[Finding]:
    """What telemetry this workspace actually ingests (last 30 days), by volume.

    Each table's finding carries its rounded GB and a one-word family label as
    evidence, and the list is sorted by GB descending -- a 250 GB/30d feed and a
    0.02 GB/30d trickle are very different claims about what this workspace can
    answer, so the volume figure the probe already computed is not discarded.
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

    tables = sorted(table_gb, key=lambda t: table_gb[t], reverse=True)
    findings = [
        Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"{len(tables)} tables ingesting in this Sentinel workspace (30d)",
            entity=Entity(kind=EntityKind.tenant, id="sentinel"),
            evidence=[Evidence(key="table_count", value=str(len(tables)))],
        )
    ]
    for t in tables:
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
    return findings


_INDICATOR_HELP = {
    "net": "an IP address or a port number (this table carries no URLs or "
    "usernames — for domains and URLs use hunt_dns_web)",
    "domain": "a domain, URL fragment, or IP",
}


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
    hours: float,
    limit: int,
) -> list[Finding]:
    """Shared execution path for every KQL telemetry surface.

    Bounding rules live here so no individual tool can forget one: time
    predicate first, retention clamp, limit clamp, and aggregate-only whenever
    no indicator narrows the scan.
    """
    if action not in n.ACTIONS:
        return [_bad_arg("action", action, ", ".join(n.ACTIONS))]
    if not n.validate_indicator(indicator, spec.indicator_kind):
        return [_bad_arg("indicator", indicator, _INDICATOR_HELP[spec.indicator_kind])]

    missing = await require_table(client, spec.table, human)
    if missing:
        return [missing]

    hours = n.clamp_hours(hours, client.retention_days)
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
        parts.append(f"| order by TimeGenerated desc | take {limit}")
    else:
        # No indicator -> aggregate. Never dump rows from a table this large.
        parts.append(
            f"| summarize Events=count() by {spec.action_field}, {spec.indicator_fields[0]}"
        )
        parts.append(f"| top {limit} by Events desc")
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
    findings = _rows_to_findings(rows, title_key, limit)
    if len(rows) >= limit:
        findings.append(
            more_available_finding(
                "sentinel", shown=len(findings),
                hint="Narrow with an indicator or a shorter hours window.",
            )
        )
    return findings


async def hunt_firewall(
    client: Any,
    action: str = "any",
    indicator: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """Firewall traffic from the CEF table (Check Point / Fortinet)."""
    return await _run_surface(
        client, n.SURFACE_SPECS["firewall"],
        cap="Sentinel firewall telemetry", human="firewall (CEF)",
        action=action, indicator=indicator, hours=hours, limit=limit,
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
    hours: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """DNS / web-proxy / RA-VPN activity from the Cisco Umbrella tables."""
    if surface not in n.SURFACES:
        return [_bad_arg("surface", surface, ", ".join(n.SURFACES))]
    return await _run_surface(
        client, n.SURFACE_SPECS[surface],
        cap=f"Sentinel {surface} telemetry", human=_SURFACE_HUMAN[surface],
        action=action, indicator=indicator, hours=hours, limit=limit,
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
    hours: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """Microsoft 365 audit activity from OfficeActivity (fast path vs. Purview)."""
    cap = "Sentinel Microsoft 365 activity"
    if workload not in n.WORKLOADS:
        return [_bad_arg("workload", workload, ", ".join(n.WORKLOADS))]
    if operation and not n.WORD_RE.match(operation):
        return [_bad_arg("operation", operation, "an exact operation name, e.g. FileDownloaded")]
    if user and not n.UPN_RE.match(user):
        return [_bad_arg("user", user, "a UPN, e.g. someone@contoso.com")]

    missing = await require_table(client, "OfficeActivity", "Microsoft 365 audit (OfficeActivity)")
    if missing:
        return [missing]

    hours = n.clamp_hours(hours, client.retention_days)
    limit = clamp_limit(limit)

    parts = ["OfficeActivity", f"| where TimeGenerated > ago({hours:g}h)"]
    if workload != "any":
        parts.append(f'| where OfficeWorkload =~ "{_WORKLOAD_VALUE[workload]}"')
    if user:
        parts.append(f'| where UserId =~ "{user}"')
    if operation:
        parts.append(f'| where Operation =~ "{operation}"')
        parts.append(f"| project {', '.join(_OA_PROJECT)}")
        parts.append(f"| order by TimeGenerated desc | take {limit}")
    else:
        # Discovery mode: hand back the operation vocabulary so the model can
        # pick a real value rather than inventing one.
        parts.append(f"| summarize Events=count() by Operation | top {limit} by Events desc")
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
            for r in rows[:limit]
        ]
    return _rows_to_findings(rows, "Operation", limit)


_SEV_ORDER = ("informational", "low", "medium", "high")
_SEV_VALUE = {
    "informational": "Informational", "low": "Low", "medium": "Medium", "high": "High",
}
_SEV_FINDING = {
    "informational": Severity.info, "low": Severity.low,
    "medium": Severity.medium, "high": Severity.high,
}
_STATUS_VALUE = {"new": "New", "active": "Active", "closed": "Closed"}


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
    status: str = "any",
    hours: float = 168,
    limit: int = 25,
) -> list[Finding]:
    """The Sentinel SOC incident queue, with MITRE tactics."""
    cap = "Sentinel incidents"
    if severity_min not in _SEV_ORDER:
        return [_bad_arg("severity_min", severity_min, ", ".join(_SEV_ORDER))]
    if status != "any" and status not in _STATUS_VALUE:
        return [_bad_arg("status", status, "new, active, closed, any")]

    missing = await require_table(client, "SecurityIncident", "Sentinel incidents")
    if missing:
        return [missing]

    hours = n.clamp_hours(hours, client.retention_days)
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
    if status != "any":
        parts.append(f'| where Status =~ "{_STATUS_VALUE[status]}"')
    parts.append("| order by TimeGenerated desc")
    parts.append(f"| take {limit}")
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
                title=f"No Sentinel incidents at severity {severity_min}+ in the last {hours:g}h",
            )
        ]

    out: list[Finding] = []
    for r in rows[:limit]:
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
    return out


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
    for r in enabled[:25]:
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
    return out


# Kusto control commands start with a dot and can mutate the workspace
# (.create, .drop, .set-or-append, .ingest). This server is read-only, so they
# never reach the API.
_CONTROL_PREFIX = "."


async def run_kql(client: Any, kql: str, hours: float = 24, limit: int = 25) -> list[Finding]:
    """Run a caller-supplied read-only KQL query, force-bounded."""
    cap = "Sentinel KQL query"
    query = (kql or "").strip()
    if not query:
        return [_bad_arg("kql", kql or "", "a KQL query, e.g. 'Heartbeat | take 10'")]
    if not query[0].isprintable():
        # Whitelist, not blacklist: str.strip() only removes ordinary
        # whitespace, so a leading invisible/control character (BOM,
        # zero-width space, C0/C1 controls, ...) can survive it and hide a
        # dot-prefixed control command from the startswith(".") check below.
        # Rather than enumerate every Unicode category that can do this,
        # reject any query that doesn't begin with an ordinary printable
        # character -- no legitimate KQL query starts with one, so this
        # closes the class by construction instead of one exploit at a time.
        return [
            Finding(
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
        ]
    if query.startswith(_CONTROL_PREFIX):
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title="Kusto control commands are not permitted — this server is read-only",
                recommended_action=RecommendedAction(
                    summary="Use a tabular query (TableName | where ... | take N).",
                    confidence="high",
                ),
            )
        ]

    hours = n.clamp_hours(hours, client.retention_days)
    limit = clamp_limit(limit)
    lowered = query.lower()
    if " take " not in lowered and " limit " not in lowered and not lowered.endswith("take"):
        query = f"{query} | take {limit}"

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
    first_col = next(iter(rows[0].keys()), "result")
    return _rows_to_findings(rows, first_col, limit)
