"""Tenable Vulnerability Management read tools -> findings.

Read-only. Each tool catches a TenableError (auth / permission / rate-limit /
gateway) and returns a graceful finding instead of crashing. Response field
names are validated by the live smoke test (recipe step 9).
"""
from __future__ import annotations

import re
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

from .errors import map_tenable_error

# Tenable severity integer 0-4 -> our Severity.
_SEV_BY_INT = {
    0: Severity.info,
    1: Severity.low,
    2: Severity.medium,
    3: Severity.high,
    4: Severity.critical,
}
# severity_min enum string -> the minimum Tenable integer to include.
_SEV_MIN = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _sev(value: Any) -> Severity:
    """Tenable severity (int 0-4, or a name) -> Severity; unknown -> info."""
    if isinstance(value, int):
        return _SEV_BY_INT.get(value, Severity.info)
    return {s.value: s for s in Severity}.get(str(value).lower(), Severity.info)


def _rows(resp: Any, key: str) -> list[dict[str, Any]]:
    """Extract a list of rows: a bare array, or ``{key: [...]}``."""
    if isinstance(resp, list):
        return resp
    if isinstance(resp, dict):
        got = resp.get(key)
        if isinstance(got, list):
            return got
    return []


def _cves(row: dict[str, Any]) -> list[Reference]:
    out: list[Reference] = []
    for cve in row.get("cves") or row.get("cve") or []:
        out.append(Reference(type="cve", id=str(cve)))
    pid = row.get("plugin_id")
    if pid is not None:
        out.append(Reference(type="tenable_plugin", id=str(pid)))
    return out


async def get_vulnerability_summary(tio: Any) -> list[Finding]:
    try:
        d = await tio.get("/workbenches/vulnerabilities")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable vulnerability summary")
        if finding:
            return [finding]
        raise
    counts = {s: 0 for s in Severity}
    for row in _rows(d, "vulnerabilities"):
        counts[_sev(row.get("severity"))] += int(row.get("count", 0) or 0)
    worst = next(
        (s for s in (Severity.critical, Severity.high, Severity.medium, Severity.low)
         if counts[s] > 0),
        Severity.info,
    )
    evidence = [Evidence(key=s.value, value=str(counts[s]))
                for s in (Severity.critical, Severity.high, Severity.medium,
                          Severity.low, Severity.info)]
    total = sum(counts.values())
    return [
        Finding(
            source="tenable",
            finding_type=FindingType.posture,
            severity=worst,
            title=f"Tenable vulnerability posture: {total} findings across the environment",
            entity=Entity(kind=EntityKind.tenant, id="tenable"),
            evidence=evidence,
            recommended_action=RecommendedAction(
                summary="Prioritize the critical/high vulnerabilities; see "
                "list_top_vulnerabilities for the fix-first list.",
            ),
        )
    ]


async def list_top_vulnerabilities(
    tio: Any, severity_min: str = "high", limit: int = 10
) -> list[Finding]:
    try:
        d = await tio.get("/workbenches/vulnerabilities")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable top vulnerabilities")
        if finding:
            return [finding]
        raise
    floor = _SEV_MIN.get(severity_min, 3)
    rows = [r for r in _rows(d, "vulnerabilities")
            if int(r.get("severity", 0) or 0) >= floor]
    rows.sort(
        key=lambda r: (int(r.get("severity", 0) or 0), float(r.get("vpr_score", 0) or 0)),
        reverse=True,
    )
    out: list[Finding] = []
    for r in rows[:limit]:
        evidence = [Evidence(key="affected_hosts", value=str(r.get("count", 0)))]
        if r.get("vpr_score") is not None:
            evidence.append(Evidence(key="vpr", value=str(r.get("vpr_score"))))
        out.append(
            Finding(
                source="tenable",
                finding_type=FindingType.misconfig,
                severity=_sev(r.get("severity")),
                title=f"Tenable: {r.get('plugin_name', 'vulnerability')} "
                f"(plugin {r.get('plugin_id', '?')})",
                entity=Entity(kind=EntityKind.rule, id=str(r.get("plugin_id", "?")),
                              name=r.get("plugin_name")),
                evidence=evidence,
                references=_cves(r),
                recommended_action=RecommendedAction(
                    summary="Review affected hosts and remediate; see "
                    "get_vulnerability_info for the fix.",
                ),
            )
        )
    return out


async def list_assets(
    tio: Any, hostname: str = "", severity_min: str = "", limit: int = 25
) -> list[Finding]:
    try:
        d = await tio.get("/workbenches/assets", params={"limit": limit} if limit else None)
    except Exception as e:
        finding = map_tenable_error(e, "Tenable assets")
        if finding:
            return [finding]
        raise
    out: list[Finding] = []
    for a in _rows(d, "assets")[:limit]:
        fqdns = a.get("fqdn") or []
        ipv4s = a.get("ipv4") or []
        name = (fqdns[0] if fqdns else (ipv4s[0] if ipv4s else a.get("id", "asset")))
        if hostname and hostname.lower() not in str(name).lower():
            continue
        evidence = []
        if a.get("last_seen"):
            evidence.append(Evidence(key="last_seen", value=str(a["last_seen"])))
        if ipv4s:
            evidence.append(Evidence(key="ipv4", value=str(ipv4s[0])))
        out.append(
            Finding(
                source="tenable",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Tenable asset: {name}",
                entity=Entity(kind=EntityKind.host, id=str(a.get("id", name)), name=str(name)),
                evidence=evidence,
                observed_at=a.get("last_seen"),
            )
        )
    return out
