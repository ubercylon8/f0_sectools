"""LimaCharlie read tools -> findings.

Read-only. Each tool catches known SDK errors (permission / rate-limit / auth)
and returns a posture finding instead of crashing. Dict key access is defensive;
the live smoke test confirms the real field names.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Reference,
    Severity,
)

from .errors import map_lc_error

# Caps to keep payloads small-model-safe.
_MAX_ITEMS = 50
_OVERVIEW_SCAN = 1000

# LimaCharlie platform architecture constants -> human names.
_PLATFORMS = {
    0x10000000: "windows",
    0x20000000: "linux",
    0x30000000: "macos",
    0x40000000: "ios",
    0x50000000: "android",
    0x60000000: "chromeos",
}


def _first(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _platform_name(value: Any) -> str:
    if isinstance(value, int):
        return _PLATFORMS.get(value, str(value))
    return str(value)


def _sensor_findings(sensors: list[dict[str, Any]], cap: int = _MAX_ITEMS) -> list[Finding]:
    out: list[Finding] = []
    for s in sensors[: min(cap, _MAX_ITEMS)]:
        host = _first(s, "hostname", "host_name", default="unknown")
        online = bool(_first(s, "is_online", "online", default=False))
        plat = _platform_name(_first(s, "platform", "plat", default="?"))
        out.append(
            Finding(
                source="limacharlie",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Sensor: {host} ({'online' if online else 'offline'})",
                entity=Entity(
                    kind=EntityKind.host, id=str(_first(s, "sid", default="")), name=str(host)
                ),
                evidence=[
                    Evidence(key="platform", value=str(plat)),
                    Evidence(key="online", value=str(online)),
                ],
            )
        )
    return out


def list_sensors(lc: Any, online_only: bool = False, limit: int = _MAX_ITEMS) -> list[Finding]:
    try:
        sensors = lc.list_sensors(online_only=online_only, limit=limit)
    except Exception as e:
        finding = map_lc_error(e, "LimaCharlie sensors", "sensor.list")
        if finding:
            return [finding]
        raise
    # The SDK does not strictly honor `limit`; enforce it on the output.
    return _sensor_findings(sensors, cap=limit)


def get_sensor(lc: Any, hostname: str) -> list[Finding]:
    try:
        result = lc.find_sensor(hostname)
    except Exception as e:
        finding = map_lc_error(e, "LimaCharlie sensor lookup", "sensor.get")
        if finding:
            return [finding]
        raise
    # find_sensor returns full sensor dicts (list); tolerate a dict-of-dicts too.
    sensors = list(result.values()) if isinstance(result, dict) else list(result or [])
    if not sensors:
        return [
            Finding(
                source="limacharlie",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"No sensor found for hostname '{hostname}'",
            )
        ]
    return _sensor_findings(sensors)


def list_dr_rules(lc: Any, namespace: str = "general", limit: int = _MAX_ITEMS) -> list[Finding]:
    try:
        rules = lc.list_dr_rules(namespace=namespace)
    except Exception as e:
        finding = map_lc_error(e, "LimaCharlie D&R rules", "dr.list.general")
        if finding:
            return [finding]
        raise
    names = list(rules.keys()) if isinstance(rules, dict) else []
    out: list[Finding] = []
    for name in names[:limit]:
        out.append(
            Finding(
                source="limacharlie",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"D&R rule: {name}",
                entity=Entity(kind=EntityKind.rule, id=str(name), name=str(name)),
                evidence=[Evidence(key="namespace", value=namespace)],
            )
        )
    return out


_DET_SEV = {0: Severity.low, 1: Severity.low, 2: Severity.medium, 3: Severity.medium,
            4: Severity.high, 5: Severity.critical}


def list_detections(
    lc: Any, hours_back: float = 24, limit: int = _MAX_ITEMS, category: str | None = None
) -> list[Finding]:
    end = int(time.time())
    start = int(end - hours_back * 3600)
    try:
        raw = lc.list_detections(start, end, limit=limit, category=category)
    except Exception as e:
        finding = map_lc_error(e, "LimaCharlie detections", "insight.det.get")
        if finding:
            return [finding]
        raise
    out: list[Finding] = []
    for d in raw[:limit]:
        routing = d.get("routing") or {}
        cat = _first(d, "cat", "category", default="detection")
        prio = d.get("priority")
        sev = _DET_SEV.get(int(prio), Severity.medium) if isinstance(prio, int) else Severity.medium
        host = _first(routing, "hostname", default=_first(d, "hostname", default=""))
        ent = (
            Entity(kind=EntityKind.host, id=str(_first(routing, "sid", default="")), name=str(host))
            if host
            else None
        )
        detect_id = str(_first(d, "detect_id", "link", default=""))
        out.append(
            Finding(
                source="limacharlie",
                finding_type=FindingType.alert,
                severity=sev,
                title=str(cat),
                entity=ent,
                evidence=[Evidence(key="detect_id", value=detect_id)],
                references=[Reference(type="mitre", id=t) for t in (d.get("mitre") or [])],
            )
        )
    return out


# Guided LCQL hunt presets — a small model picks one instead of writing LCQL.
# `{sel}` is the sensor selector: `*` (all sensors) or `hostname == "<host>"`.
_HUNT_PRESETS = {
    "new_processes": "{t} | {sel} | NEW_PROCESS | * | event/FILE_PATH event/COMMAND_LINE",
    "powershell_activity": (
        '{t} | {sel} | NEW_PROCESS | event/FILE_PATH contains "powershell" '
        "| event/FILE_PATH event/COMMAND_LINE"
    ),
    "dns_requests": "{t} | {sel} | DNS_REQUEST | * | event/DOMAIN_NAME",
    "network_connections": "{t} | {sel} | NETWORK_CONNECTIONS | * | event/NETWORK_ACTIVITY",
}

# LCQL string literals are double-quoted; only allow hostnames that can't break out.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _time_descriptor(hours_back: float) -> str:
    """LCQL relative-time token. Whole hours -> '-Nh'; sub-hour -> '-Nm' (minutes),
    so a small model asking for '15 minutes' (hours_back=0.25) works."""
    if hours_back >= 1 and float(hours_back).is_integer():
        return f"-{int(hours_back)}h"
    return f"-{max(1, round(hours_back * 60))}m"


def _flat_value(v: Any) -> str:
    """Serialize an (already-redacted) projection value for evidence. Nested
    (list/dict) projections like event/NETWORK_ACTIVITY are compact-JSON'd, not
    dropped (dropping them produced empty findings). Bounded by the caller."""
    if isinstance(v, dict | list):
        return json.dumps(v, default=str)
    return str(v)


def _telemetry_events(rows: Any) -> list[dict[str, Any]]:
    """lc.query returns result ENVELOPES ({..., "rows": [event, ...]}), not flat
    events — and one envelope can be hundreds of KB. Flatten to the actual events."""
    events: list[dict[str, Any]] = []
    for env in rows or []:
        if isinstance(env, dict) and isinstance(env.get("rows"), list):
            events.extend(e for e in env["rows"] if isinstance(e, dict))
        elif isinstance(env, dict):
            events.append(env)
    return events


def query_telemetry(
    lc: Any,
    hunt: str = "new_processes",
    hours_back: float = 24,
    limit: int = _MAX_ITEMS,
    hostname: str | None = None,
    lcql: str | None = None,
) -> list[Finding]:
    end = int(time.time())
    start = int(end - hours_back * 3600)
    # Scope is only meaningful on the guided preset path; a raw lcql override ignores
    # `hostname`, so don't mislabel the summary/entity by it. An empty hostname ("",
    # which a small model may emit for the optional arg) means unscoped, not invalid.
    scope_host = hostname if (hostname and lcql is None) else None
    if not lcql:
        if hostname and not _HOSTNAME_RE.match(hostname):
            return [
                Finding(
                    source="limacharlie",
                    finding_type=FindingType.posture,
                    severity=Severity.info,
                    title=f"Invalid hostname '{hostname}' — telemetry query not run",
                    recommended_action=RecommendedAction(
                        summary="hostname may contain only letters, digits, '.', '-', '_'.",
                    ),
                )
            ]
        sel = f'hostname == "{hostname}"' if hostname else "*"
        template = _HUNT_PRESETS.get(hunt, _HUNT_PRESETS["new_processes"])
        lcql = template.format(t=_time_descriptor(hours_back), sel=sel)
    try:
        rows = lc.query(lcql, start, end, limit=limit)
    except Exception as e:
        finding = map_lc_error(e, "LimaCharlie telemetry query", "insight.evt.get")
        if finding:
            return [finding]
        raise
    events = _telemetry_events(rows)
    total = len(events)
    scope = f" on {scope_host}" if scope_host else ""
    out: list[Finding] = [
        Finding(
            source="limacharlie",
            finding_type=FindingType.hunt_result,
            severity=Severity.info,
            title=f"{total} telemetry event(s){scope}"
            + (f" (showing first {limit})" if total > limit else ""),
            entity=(
                Entity(kind=EntityKind.host, id=str(scope_host), name=str(scope_host))
                if scope_host
                else None
            ),
            evidence=[
                Evidence(key="events_total", value=str(total)),
                Evidence(key="lcql", value=lcql),
            ],
            recommended_action=RecommendedAction(
                summary="Review the events; refine the hunt/hostname to investigate further."
            ),
        )
    ]
    for ev in events[:limit]:
        data = ev.get("data") if isinstance(ev.get("data"), dict) else ev
        # Redact the whole event data ONCE, before anything is flattened to a string:
        # key-hint redaction (e.g. an event/CLIENT_SECRET field) + value patterns +
        # nested keys. Stringifying first defeats redact_obj's key-hint pass, and a
        # secret-named field becomes the VALUE of Evidence.key (which the boundary,
        # keying off 'key'/'value', can't redact). The server boundary redacts again.
        data = redact_obj(data or {})
        ev_evidence = [
            Evidence(key=str(k).split("/")[-1].lower(), value=_flat_value(v)[:300])
            for k, v in list(data.items())[:6]
        ]
        title = next((str(v) for v in data.values() if isinstance(v, str) and v), "")
        if not title and data:
            title = _flat_value(next(iter(data.values())))
        title = title or "telemetry event"
        out.append(
            Finding(
                source="limacharlie",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=str(title)[:200],
                evidence=ev_evidence,
            )
        )
    return out


def get_org_overview(lc: Any) -> list[Finding]:
    try:
        info = lc.org_info()
        sensors = lc.list_sensors(limit=_OVERVIEW_SCAN)
        rules = lc.list_dr_rules()
        end = int(time.time())
        detections = lc.list_detections(end - 24 * 3600, end, limit=_OVERVIEW_SCAN)
    except Exception as e:
        finding = map_lc_error(e, "LimaCharlie org overview", "org.get")
        if finding:
            return [finding]
        raise
    online = sum(1 for s in sensors if bool(_first(s, "is_online", "online", default=False)))
    n_rules = len(rules) if isinstance(rules, dict) else 0
    name = _first(info, "name", "oid", default="organization")
    title = f"Org '{name}': {len(sensors)} sensors, {len(detections)} detections (24h)"
    return [
        Finding(
            source="limacharlie",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=title,
            entity=Entity(kind=EntityKind.tenant, id=str(_first(info, "oid", default="org"))),
            evidence=[
                Evidence(key="sensors_total", value=str(len(sensors))),
                Evidence(key="sensors_online", value=str(online)),
                Evidence(key="dr_rules", value=str(n_rules)),
                Evidence(key="detections_24h", value=str(len(detections))),
            ],
            recommended_action=RecommendedAction(
                summary="Review online vs offline sensors and recent activity; "
                "investigate a notable endpoint, or check detection coverage."
            ),
        )
    ]
