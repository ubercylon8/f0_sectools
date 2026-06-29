"""LimaCharlie read tools -> findings.

Read-only. Each tool catches known SDK errors (permission / rate-limit / auth)
and returns a posture finding instead of crashing. Dict key access is defensive;
the live smoke test confirms the real field names.
"""
from __future__ import annotations

import time
from typing import Any

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


def _first(d: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _platform_name(value: Any) -> str:
    if isinstance(value, int):
        return _PLATFORMS.get(value, str(value))
    return str(value)


def _sensor_findings(sensors: list[dict], cap: int = _MAX_ITEMS) -> list[Finding]:
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
    # find_sensors_by_hostname returns a dict keyed by sid (or a list); normalize.
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
    lc: Any, hours_back: int = 24, limit: int = _MAX_ITEMS, category: str | None = None
) -> list[Finding]:
    end = int(time.time())
    start = end - hours_back * 3600
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


def query_telemetry(
    lc: Any, lcql: str, hours_back: int = 24, limit: int = _MAX_ITEMS
) -> list[Finding]:
    end = int(time.time())
    start = end - hours_back * 3600
    try:
        rows = lc.query(lcql, start, end, limit=limit)
    except Exception as e:
        finding = map_lc_error(e, "LimaCharlie telemetry query", "insight.evt.get")
        if finding:
            return [finding]
        raise
    sample = rows[:limit]
    evidence = [Evidence(key=f"row_{i}", value=str(r)) for i, r in enumerate(sample)]
    return [
        Finding(
            source="limacharlie",
            finding_type=FindingType.hunt_result,
            severity=Severity.info,
            title=f"LCQL query returned {len(rows)} row(s)"
            + (f" (showing first {limit})" if len(rows) > limit else ""),
            evidence=evidence,
            recommended_action=RecommendedAction(
                summary="Review the rows; refine the LCQL to investigate further."
            ),
        )
    ]


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
                summary="Review detection volume vs D&R coverage; investigate notable detections."
            ),
        )
    ]
