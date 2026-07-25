"""Tenable Vulnerability Management read tools -> findings.

Read-only. Each tool catches a TenableError (auth / permission / rate-limit /
gateway) and returns a graceful finding instead of crashing. Response field
names are validated by the live smoke test (recipe step 9).
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

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


_SEV_RANK = {Severity.info: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3,
             Severity.critical: 4}


def _sev_rank(value: Any) -> int:
    """Tolerant severity rank 0-4 (reuses _sev, which accepts int or name)."""
    return _SEV_RANK[_sev(value)]


def _num(value: Any) -> float:
    """Tolerant float; non-numeric -> 0.0 (never raises)."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


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


def _cvss(row: dict[str, Any]) -> str | None:
    """Best CVSS base score from a Workbenches vuln row: CVSSv3 preferred, else v2.

    The Workbenches vulnerabilities list carries CVSS (cvss3_base_score /
    cvss_base_score), not VPR — VPR is only on the per-plugin /info endpoint.
    """
    for key in ("cvss3_base_score", "cvss_base_score"):
        v = row.get(key)
        if v not in (None, ""):
            return str(v)
    return None


def _info_cves(info: dict[str, Any]) -> list[str]:
    """CVE ids from a plugin /info 'reference_information' block (name == 'cve')."""
    out: list[str] = []
    for ref in info.get("reference_information") or []:
        if isinstance(ref, dict) and str(ref.get("name", "")).lower() == "cve":
            out.extend(str(v) for v in ref.get("values") or [])
    return out


def _epoch_to_iso(value: Any) -> str:
    """Unix epoch seconds -> ISO-8601 UTC; non-numeric values pass through unchanged.

    Tenable's /scans returns last_modification_date as a unix timestamp; an ISO
    date is what a model needs to judge scan freshness.
    """
    try:
        return datetime.fromtimestamp(int(value), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError):
        return str(value)


# Workbenches returns the WHOLE result set in one payload — live-probed
# 2026-07-25: /workbenches/assets 314 rows, /workbenches/vulnerabilities 673,
# /scans 141, none carrying a paging signal. So the pool length IS the total,
# and a bounded page that says nothing reads as "this is everything".


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
    evidence = [Evidence(key="headline", value=f"{counts[Severity.critical]} critical")] + [
        Evidence(key=s.value, value=str(counts[s]))
        for s in (Severity.critical, Severity.high, Severity.medium,
                  Severity.low, Severity.info)
    ]
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
    limit = clamp_limit(limit)
    try:
        d = await tio.get("/workbenches/vulnerabilities")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable top vulnerabilities")
        if finding:
            return [finding]
        raise
    floor = _SEV_MIN.get(severity_min, 3)
    rows = [r for r in _rows(d, "vulnerabilities")
            if _sev_rank(r.get("severity")) >= floor]
    rows.sort(
        key=lambda r: (_sev_rank(r.get("severity")), _num(_cvss(r))),
        reverse=True,
    )
    out: list[Finding] = []
    for r in rows[:limit]:
        evidence = [Evidence(key="affected_hosts", value=str(r.get("count", 0)))]
        cvss = _cvss(r)
        if cvss is not None:
            evidence.append(Evidence(key="cvss", value=cvss))
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
    note = truncation_finding(
        "tenable", shown=len(out), fetched=len(out), total=len(rows),
        hint="Raise severity_min to prioritize, or raise limit to see more.",
    )
    if note:
        out.append(note)
    return out


async def list_assets(tio: Any, hostname: str = "", limit: int = 25) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        params = None if hostname else ({"limit": limit} if limit else None)
        d = await tio.get("/workbenches/assets", params=params)
    except Exception as e:
        finding = map_tenable_error(e, "Tenable assets")
        if finding:
            return [finding]
        raise
    out: list[Finding] = []
    matched = 0
    for a in _rows(d, "assets"):
        fqdns = a.get("fqdn") or []
        ipv4s = a.get("ipv4") or []
        name = fqdns[0] if fqdns else (ipv4s[0] if ipv4s else a.get("id", "asset"))
        if hostname and hostname.lower() not in str(name).lower():
            continue
        matched += 1
        if len(out) >= limit:
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
    # Two paths, two different truncation signals:
    #  - hostname given: params is None, so the WHOLE workbench was fetched and
    #    filtered here. `matched` is the true count of matching assets.
    #  - no hostname: the API bounded the page, so the pool size is unknown. Its
    #    own `total` field cannot stand in — live-probed 2026-07-25, ?limit=10
    #    reports total=580 while an unbounded fetch returns 314 assets with
    #    total=314, so quoting 580 would contradict what the tool itself returns.
    #    A full page is the honest signal; it over-warns only when the asset
    #    count is exactly `limit`.
    if hostname:
        note = truncation_finding("tenable", shown=len(out), fetched=len(out), total=matched)
    else:
        note = truncation_finding(
            "tenable", shown=len(out), fetched=len(out), has_more=len(out) >= limit,
        )
    if note:
        out.append(note)
    return out


async def _resolve_asset_uuid(tio: Any, asset: str) -> str | None:
    """A UUID passes through; else match the first asset whose fqdn/ipv4 contains `asset`."""
    if _UUID_RE.match(asset):
        return asset
    d = await tio.get("/workbenches/assets")
    needle = asset.lower()
    for a in _rows(d, "assets"):
        hay = " ".join(str(x).lower() for x in
                       (a.get("fqdn") or []) + (a.get("ipv4") or []) + [a.get("id", "")])
        if needle in hay:
            return str(a.get("id"))
    return None


async def get_asset_vulnerabilities(
    tio: Any, asset: str, severity_min: str = "high", limit: int = 25
) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        uuid = await _resolve_asset_uuid(tio, asset)
        if uuid is None:
            return [Finding(
                source="tenable",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Tenable: no asset matches '{asset}'",
                recommended_action=RecommendedAction(
                    summary="Check the hostname/IP, or list_assets to find the exact name.",
                ),
            )]
        d = await tio.get(f"/workbenches/assets/{uuid}/vulnerabilities")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable asset vulnerabilities")
        if finding:
            return [finding]
        raise
    floor = _SEV_MIN.get(severity_min, 3)
    rows = [r for r in _rows(d, "vulnerabilities")
            if _sev_rank(r.get("severity")) >= floor]
    rows.sort(key=lambda r: _sev_rank(r.get("severity")), reverse=True)
    out: list[Finding] = []
    for r in rows[:limit]:
        out.append(
            Finding(
                source="tenable",
                finding_type=FindingType.misconfig,
                severity=_sev(r.get("severity")),
                title=f"Tenable: {r.get('plugin_name', 'vulnerability')} on {asset}",
                entity=Entity(kind=EntityKind.host, id=str(uuid), name=asset),
                evidence=[Evidence(key="instances", value=str(r.get("count", 0)))],
                references=_cves(r),
            )
        )
    note = truncation_finding(
        "tenable", shown=len(out), fetched=len(out), total=len(rows),
        hint="Raise severity_min to prioritize, or raise limit to see more.",
    )
    if note:
        out.append(note)
    return out


async def get_vulnerability_info(tio: Any, plugin_id: str) -> list[Finding]:
    try:
        d = await tio.get(f"/workbenches/vulnerabilities/{plugin_id}/info")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable vulnerability detail")
        if finding:
            return [finding]
        raise
    info = d.get("info", {}) if isinstance(d, dict) else {}
    details = info.get("plugin_details", {})
    name = details.get("name", f"plugin {plugin_id}")
    evidence = []
    if info.get("description"):
        evidence.append(Evidence(key="description", value=str(info["description"])[:500]))
    if info.get("solution"):
        evidence.append(Evidence(key="solution", value=str(info["solution"])[:500]))
    risk = info.get("risk_information") or {}
    cvss = risk.get("cvss3_base_score") or risk.get("cvss_base_score")
    if cvss:
        evidence.append(Evidence(key="cvss", value=str(cvss)))
    vpr = info.get("vpr") or {}
    if isinstance(vpr, dict) and vpr.get("score") is not None:
        evidence.append(Evidence(key="vpr", value=str(vpr["score"])))
    refs = [Reference(type="cve", id=str(c)) for c in _info_cves(info)]
    refs.append(Reference(type="tenable_plugin", id=str(plugin_id)))
    return [
        Finding(
            source="tenable",
            finding_type=FindingType.misconfig,
            severity=_sev(details.get("severity")),
            title=f"Tenable plugin {plugin_id}: {name}",
            entity=Entity(kind=EntityKind.rule, id=str(plugin_id), name=name),
            evidence=evidence,
            references=refs,
            recommended_action=RecommendedAction(
                summary="Apply the solution above to the affected assets.",
            ),
        )
    ]


async def list_scans(tio: Any, limit: int = 25) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        d = await tio.get("/scans")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable scans")
        if finding:
            return [finding]
        raise
    # /scans comes back unordered (live-probed 2026-07-25: 141 scans, not
    # newest-first), so "recent scans" was whatever the API happened to list
    # first. Sort newest-first on last_modification_date; the 104 of 141 scans
    # that carry no date sort last rather than being dropped or crashing the key.
    scans = sorted(_rows(d, "scans"), key=lambda s: _num(s.get("last_modification_date")),
                   reverse=True)
    out: list[Finding] = []
    for s in scans[:limit]:
        evidence = [Evidence(key="status", value=str(s.get("status", "unknown")))]
        if s.get("last_modification_date"):
            evidence.append(
                Evidence(key="last_run", value=_epoch_to_iso(s.get("last_modification_date"))))
        out.append(
            Finding(
                source="tenable",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Tenable scan: {s.get('name', s.get('id', 'scan'))}",
                entity=Entity(kind=EntityKind.rule, id=str(s.get("id", "?")),
                              name=s.get("name")),
                evidence=evidence,
            )
        )
    note = truncation_finding("tenable", shown=len(out), fetched=len(out), total=len(scans))
    if note:
        out.append(note)
    return out


def _plugin_output_assets(d: Any) -> list[dict[str, Any]]:
    """Affected assets from a Workbenches plugin /outputs payload, deduped by id.

    Shape (LIVE-VALIDATION-PENDING, recipe step 9): outputs[] -> states[] ->
    results[] -> assets[] with id/hostname/fqdn/ipv4. Defensive against missing
    levels AND wrong-typed ones — an unexpected live shape must degrade to "no
    assets", never raise (Critical Rule 4).
    """
    seen: dict[str, dict[str, Any]] = {}
    outputs = d.get("outputs") if isinstance(d, dict) else None
    for o in outputs or []:
        if not isinstance(o, dict):
            continue
        for st in o.get("states") or []:
            if not isinstance(st, dict):
                continue
            for res in st.get("results") or []:
                if not isinstance(res, dict):
                    continue
                for a in res.get("assets") or []:
                    if not isinstance(a, dict):
                        continue
                    aid = str(a.get("id") or a.get("uuid") or a.get("hostname") or "")
                    if aid and aid not in seen:
                        seen[aid] = a
    return list(seen.values())


async def list_vulnerability_assets(
    tio: Any, plugin_id: str, limit: int = 25
) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        d = await tio.get(f"/workbenches/vulnerabilities/{plugin_id}/outputs")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable plugin affected hosts")
        if finding:
            return [finding]
        raise
    assets = _plugin_output_assets(d)
    if not assets:
        return [
            Finding(
                source="tenable",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Tenable: no affected assets found for plugin {plugin_id}",
                entity=Entity(kind=EntityKind.rule, id=str(plugin_id)),
                recommended_action=RecommendedAction(
                    summary="Confirm the plugin_id (see list_top_vulnerabilities); the "
                    "finding may also be aged out (>450 days).",
                ),
            )
        ]
    out: list[Finding] = []
    for a in assets[:limit]:
        fqdns = a.get("fqdn") or []
        ipv4s = a.get("ipv4") or []
        name = a.get("hostname") or (fqdns[0] if fqdns else None) \
            or (ipv4s[0] if ipv4s else a.get("id", "asset"))
        evidence = []
        if ipv4s:
            evidence.append(Evidence(key="ipv4", value=str(ipv4s[0])))
        if a.get("last_seen"):
            evidence.append(Evidence(key="last_seen", value=str(a["last_seen"])))
        out.append(
            Finding(
                source="tenable",
                finding_type=FindingType.misconfig,
                severity=Severity.info,
                title=f"Tenable: {name} affected by plugin {plugin_id}",
                entity=Entity(kind=EntityKind.host, id=str(a.get("id", name)), name=str(name)),
                evidence=evidence,
                references=[Reference(type="tenable_plugin", id=str(plugin_id))],
                observed_at=a.get("last_seen"),
            )
        )
    if len(assets) > limit:
        out.append(more_available_finding("tenable", shown=limit, total=len(assets)))
    return out
