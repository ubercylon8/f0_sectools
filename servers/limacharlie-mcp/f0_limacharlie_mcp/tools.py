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

from f0_sectools_core.paging import clamp_limit
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

# Sensors carrying this tag are DORMANT: they stay enrolled/online but collect no
# telemetry. Surfacing it is the only way to tell "dormant by design" from "quiet".
_SLEEPER_TAG = "lc:sleeper"

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


def _sensor_findings(
    sensors: list[dict[str, Any]],
    cap: int = _MAX_ITEMS,
    tags_by_sid: dict[str, list[str]] | None = None,
) -> list[Finding]:
    out: list[Finding] = []
    for s in sensors[: min(cap, _MAX_ITEMS)]:
        host = _first(s, "hostname", "host_name", default="unknown")
        online = bool(_first(s, "is_online", "online", default=False))
        plat = _platform_name(_first(s, "platform", "plat", default="?"))
        evidence = [
            Evidence(key="platform", value=str(plat)),
            Evidence(key="online", value=str(online)),
        ]
        state = "online" if online else "offline"
        tags = (tags_by_sid or {}).get(str(_first(s, "sid", default="")))
        if tags is not None:
            evidence.append(Evidence(key="tags", value=", ".join(tags) or "none"))
            if _SLEEPER_TAG in tags:
                state += ", dormant sleeper — collects no telemetry"
        out.append(
            Finding(
                source="limacharlie",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Sensor: {host} ({state})",
                entity=Entity(
                    kind=EntityKind.host, id=str(_first(s, "sid", default="")), name=str(host)
                ),
                evidence=evidence,
            )
        )
    return out


def _resolve_sensor(
    lc: Any, hostname: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve a short hostname or FQDN to live sensor records.

    The platform lookup is a PREFIX match; a hostname is only accepted at a dot
    boundary ("sbl8042" -> "sbl8042.supernet.gov.do", but "sbl80" matches nothing
    exactly). Returns (boundary_matches, all_prefix_matches) — the latter feeds
    the disambiguation finding when the boundary match is empty or ambiguous.
    """
    prefix = [s for s in (lc.find_sensor(hostname) or []) if not s.get("is_del")]
    exact = [
        s
        for s in prefix
        if s.get("hostname") == hostname
        or str(s.get("hostname", "")).startswith(hostname + ".")
    ]
    return exact, prefix


def list_sensors(lc: Any, online_only: bool = False, limit: int = _MAX_ITEMS) -> list[Finding]:
    limit = clamp_limit(limit)
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
    # Tags need one extra call per sensor; get_sensor returns few, so bound at 5.
    # A tags failure degrades to rendering without tags, never to an exception.
    tags_by_sid: dict[str, list[str]] = {}
    for s in sensors[:5]:
        sid = str(_first(s, "sid", default=""))
        if not sid:
            continue
        try:
            fetched = lc.get_sensor_tags(sid)
        except Exception:  # noqa: BLE001 — tags are enrichment, not the record
            fetched = None
        if fetched is not None:
            tags_by_sid[sid] = fetched
    return _sensor_findings(sensors, tags_by_sid=tags_by_sid)


def list_dr_rules(lc: Any, namespace: str = "general", limit: int = _MAX_ITEMS) -> list[Finding]:
    limit = clamp_limit(limit)
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
    limit = clamp_limit(limit)
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

# LCQL string literals are double-quoted; only allow values that can't break out.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.*_-]+$")


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
    """lc.query returns a STREAM of result objects ({..., "rows": [event, ...]}),
    not flat events — and one can be hundreds of KB. Only the "events" object carries
    a `rows` LIST; the others (type=timeline/facets/timeseries) have rows=None and are
    search METADATA, not telemetry — extract only real event rows, drop the rest."""
    events: list[dict[str, Any]] = []
    for env in rows or []:
        if isinstance(env, dict) and isinstance(env.get("rows"), list):
            events.extend(e for e in env["rows"] if isinstance(e, dict))
    return events


def query_telemetry(
    lc: Any,
    hunt: str = "new_processes",
    hours_back: float = 24,
    limit: int = _MAX_ITEMS,
    hostname: str | None = None,
    domain: str | None = None,
    lcql: str | None = None,
) -> list[Finding]:
    limit = clamp_limit(limit)
    end = int(time.time())
    start = int(end - hours_back * 3600)
    # Scope is only meaningful on the guided preset path; a raw lcql override ignores
    # `hostname`/`domain`, so don't mislabel the summary/entity by them. An empty
    # value ("", which a small model may emit for an optional arg) means unset.
    scope_host = hostname if (hostname and lcql is None) else None
    scope_domain: str | None = None  # set to the base domain actually queried, below
    resolved_sensor: dict[str, Any] | None = None  # the record scoping resolved to
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
        if domain and not _DOMAIN_RE.match(domain):
            return [
                Finding(
                    source="limacharlie",
                    finding_type=FindingType.posture,
                    severity=Severity.info,
                    title=f"Invalid domain '{domain}' — telemetry query not run",
                    recommended_action=RecommendedAction(
                        summary="domain may contain only letters, digits, '.', '*', '-', '_'.",
                    ),
                )
            ]
        # Sensors register their FULL hostname (often an FQDN); the LCQL selector is
        # an exact match, so a short name like "sbl8042" silently selects ZERO sensors
        # — indistinguishable from a quiet host (live repro: 0 vs 954 real events).
        # Resolve the name the same way get_sensor does (prefix lookup, accepted only
        # at a dot boundary) and scope by the STORED hostname, which also covers
        # re-enrolled duplicate sensor records sharing that hostname.
        if scope_host:
            try:
                exact, prefix = _resolve_sensor(lc, scope_host)
            except Exception as e:
                finding = map_lc_error(e, "LimaCharlie sensor lookup", "sensor.list")
                if finding:
                    return [finding]
                raise
            hostnames = sorted({str(s["hostname"]) for s in exact if s.get("hostname")})
            if len(hostnames) == 1:
                # Prefer an online record for the later state/tags diagnosis.
                resolved_sensor = next(
                    (s for s in exact if _first(s, "is_online", "online", default=False)),
                    exact[0],
                )
                scope_host = hostnames[0]
            else:
                candidates = sorted(
                    {str(s["hostname"]) for s in prefix if s.get("hostname")}
                )[:5]
                if not candidates:
                    return [
                        Finding(
                            source="limacharlie",
                            finding_type=FindingType.posture,
                            severity=Severity.info,
                            title=f"No sensor matched hostname '{scope_host}' — "
                            "telemetry query not run",
                            recommended_action=RecommendedAction(
                                summary="Check the spelling, or use list_sensors to "
                                "see enrolled hostnames.",
                            ),
                        )
                    ]
                return [
                    Finding(
                        source="limacharlie",
                        finding_type=FindingType.posture,
                        severity=Severity.info,
                        title=f"Hostname '{scope_host}' matches {len(candidates)} sensors "
                        "— telemetry query not run",
                        evidence=[
                            Evidence(key="matching_hostnames", value=", ".join(candidates))
                        ],
                        recommended_action=RecommendedAction(
                            summary="Re-run with one of the matching hostnames.",
                        ),
                    )
                ]
        sel = f'hostname == "{scope_host}"' if scope_host else "*"
        td = _time_descriptor(hours_back)
        # A leading "*." is a wildcard; strip it to the base domain. A base that is
        # empty or all-wildcard (domain="", "*", "*.") is NOT a meaningful filter —
        # it must fall through to the preset, never become `contains ""` (match-all).
        base = domain[2:] if (domain and domain.startswith("*.")) else (domain or "")
        if base.strip("*."):
            # Domains live in DNS_REQUEST, not NETWORK_CONNECTIONS (which has IPs) —
            # route domain questions to DNS. Anchor on the domain BOUNDARY (exact apex
            # `is "x"` OR a proper subdomain `ends with ".x"`) rather than a bare
            # `contains`, so a lookalike like `microsoft.com.evil.net` is NOT reported
            # as matching. (`is`/`ends with`/`or` are valid LCQL query-filter operators,
            # confirmed live.)
            lcql = (
                f'{td} | {sel} | DNS_REQUEST '
                f'| event/DOMAIN_NAME is "{base}" or event/DOMAIN_NAME ends with ".{base}" '
                f'| event/DOMAIN_NAME'
            )
            scope_domain = base  # label matches what we actually queried
        else:
            template = _HUNT_PRESETS.get(hunt, _HUNT_PRESETS["new_processes"])
            lcql = template.format(t=td, sel=sel)
    try:
        rows = lc.query(lcql, start, end, limit=limit)
    except Exception as e:
        finding = map_lc_error(e, "LimaCharlie telemetry query", "insight.evt.get")
        if finding:
            return [finding]
        raise
    events = _telemetry_events(rows)
    total = len(events)
    scope = "".join(
        part for part in (
            f" on {scope_host}" if scope_host else "",
            f" matching {scope_domain}" if scope_domain else "",
        )
    )
    summary_evidence = [
        Evidence(key="events_total", value=str(total)),
        Evidence(key="lcql", value=lcql),
    ]
    if scope_domain:
        summary_evidence.append(Evidence(
            key="domain_match",
            value=f"boundary-anchored: exact {scope_domain} or a subdomain of it "
                  f"(lookalikes like {scope_domain}.evil.net are excluded)",
        ))
    # A zero-result on a resolved host needs a DIAGNOSIS, not a bare count: on this
    # class of fleet most sensors are lc:sleeper-dormant, and without saying so the
    # agent invents wrong explanations ("recently rebooted"). Tags cost one extra
    # call, spent only on the zero-result path; a tags failure just skips the note.
    action = "Review the events; refine the hunt/hostname to investigate further."
    title_note = ""
    if total == 0 and resolved_sensor is not None:
        online = bool(_first(resolved_sensor, "is_online", "online", default=False))
        summary_evidence.append(Evidence(key="sensor_online", value=str(online)))
        tags: list[str] | None
        try:
            tags = lc.get_sensor_tags(str(_first(resolved_sensor, "sid", default="")))
        except Exception:  # noqa: BLE001 — diagnosis is best-effort enrichment
            tags = None
        if tags is not None:
            summary_evidence.append(Evidence(key="tags", value=", ".join(tags) or "none"))
        if tags is not None and _SLEEPER_TAG in tags:
            title_note = " — host is dormant (lc:sleeper)"
            action = (
                "This sensor is tagged lc:sleeper: it is dormant and collects no "
                "telemetry by design. Remove the tag in LimaCharlie to resume collection."
            )
        elif not online:
            title_note = " — sensor is offline"
            action = "The sensor is offline and reporting no telemetry; check the host."
        else:
            action = (
                "No events in this window; the sensor is online. Widen hours_back "
                "or try another hunt preset."
            )
    out: list[Finding] = [
        Finding(
            source="limacharlie",
            finding_type=FindingType.hunt_result,
            severity=Severity.info,
            title=f"{total} telemetry event(s){scope}"
            + (f" (showing first {limit})" if total > limit else "")
            + title_note,
            entity=(
                Entity(
                    kind=EntityKind.host,
                    id=str(_first(resolved_sensor or {}, "sid", default=scope_host)),
                    name=str(scope_host),
                )
                if scope_host
                else None
            ),
            evidence=summary_evidence,
            recommended_action=RecommendedAction(summary=action),
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
    # Dormant (lc:sleeper) sensors collect NO telemetry — on some fleets that is
    # most of the org, which reframes every other number here. Best-effort: a
    # census failure (e.g. missing tag permission) just omits the line.
    sleepers: int | None
    try:
        sleepers = lc.count_sensors_with_tag(_SLEEPER_TAG)
    except Exception:  # noqa: BLE001 — census is enrichment, not the overview
        sleepers = None
    title = f"Org '{name}': {len(sensors)} sensors, {len(detections)} detections (24h)"
    if sleepers:
        title = (
            f"Org '{name}': {len(sensors)} sensors ({sleepers} dormant sleepers), "
            f"{len(detections)} detections (24h)"
        )
    evidence = [
        Evidence(key="sensors_total", value=str(len(sensors))),
        Evidence(key="sensors_online", value=str(online)),
        Evidence(key="dr_rules", value=str(n_rules)),
        Evidence(key="detections_24h", value=str(len(detections))),
    ]
    if sleepers is not None:
        evidence.insert(2, Evidence(key="sensors_dormant_sleepers", value=str(sleepers)))
    return [
        Finding(
            source="limacharlie",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=title,
            entity=Entity(kind=EntityKind.tenant, id=str(_first(info, "oid", default="org"))),
            evidence=evidence,
            recommended_action=RecommendedAction(
                summary="Review online vs offline sensors and recent activity; "
                "investigate a notable endpoint, or check detection coverage."
                + (
                    " Note: dormant (lc:sleeper) sensors report no telemetry."
                    if sleepers
                    else ""
                )
            ),
        )
    ]
