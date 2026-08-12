"""Platform-aware finding gather for reports. Lives in scripts/ (may import
servers/*); core/reports stays platform-free. Each persona gathers its own
groups (GATHER_MAP) — the CISO the seven-pillar rollup, the operational personas
their working data. Each factory mirrors the matching live_smoke_*.py client
construction. A platform that raises degrades to a posture finding so the report
still generates (graceful-partial)."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from dotenv import load_dotenv
from f0_sectools_core.redaction.redact import redact_finding, redact_text
from f0_sectools_core.reports.content import MetricCard, ScopeMeta
from f0_sectools_core.reports.i18n import group_label
from f0_sectools_core.reports.sections import is_not_assessed
from f0_sectools_core.schema.findings import Evidence, Finding, FindingType, Severity


def _within_window(findings: list[Finding], window_hours: int) -> list[Finding]:
    """Keep findings observed inside the report window.

    Defender's alert/incident tools have no time parameter, but the report
    subtitle asserts a window — so scope them here. A finding with no parsable
    observed_at is KEPT (we cannot judge it; silently dropping would understate).
    """
    from datetime import UTC, datetime, timedelta
    cutoff = datetime.now(UTC) - timedelta(hours=window_hours)
    kept: list[Finding] = []
    for f in findings:
        if not f.observed_at:
            kept.append(f)
            continue
        try:
            ts = datetime.fromisoformat(f.observed_at.replace("Z", "+00:00"))
        except ValueError:
            kept.append(f)
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        if ts >= cutoff:
            kept.append(f)
    return kept


def _degraded(group: str, detail: str) -> Finding:
    human = group_label("en", group)
    return Finding(
        source=group,
        finding_type=FindingType.posture,
        severity=Severity.info,
        # "not configured" is the marker sections.is_not_assessed matches — keep it.
        title=f"{human} not configured — not assessed",
        evidence=[Evidence(key="reason", value=redact_text(detail)[:300])],
    )


# ── CISO pillar factories (each returns list[Finding]) ───────────────
async def _pillar_config_hardening(window_hours: int) -> list[Finding]:
    from f0_defender_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.defender")
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return await tools.get_secure_score(gc)


async def _pillar_vuln_exposure(window_hours: int) -> list[Finding]:
    from f0_sectools_core.auth.config import TenableConfig
    from f0_tenable_mcp import tools
    from f0_tenable_mcp.client import TenableClient
    load_dotenv(".env.tenable")
    async with TenableClient(TenableConfig.from_env()) as tio:
        return await tools.get_vulnerability_summary(tio)


async def _pillar_device_compliance(window_hours: int) -> list[Finding]:
    from f0_intune_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.intune")
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return await tools.get_compliance_summary(gc)


async def _pillar_data_risk(window_hours: int) -> list[Finding]:
    from f0_purview_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.purview")
    cfg = PlatformConfig.from_env("PURVIEW")
    async with GraphClient(cfg) as gc:
        return await tools.get_dlp_summary(gc, hours_back=window_hours)


async def _pillar_attack_validation(window_hours: int) -> list[Finding]:
    from f0_projectachilles_mcp import tools
    from f0_projectachilles_mcp.client import ProjectAchillesClient
    from f0_sectools_core.auth.config import ProjectAchillesConfig
    load_dotenv(".env.projectachilles")
    async with ProjectAchillesClient(ProjectAchillesConfig.from_env()) as pa:
        return await tools.get_defense_score(pa)


async def _pillar_endpoint_coverage(window_hours: int) -> list[Finding]:
    from f0_limacharlie_mcp import tools
    from f0_limacharlie_mcp.client import LimaCharlieClient
    from f0_sectools_core.auth.config import LimaCharlieConfig
    load_dotenv(".env.limacharlie")
    lc = LimaCharlieClient(LimaCharlieConfig.from_env())
    return await asyncio.to_thread(tools.get_org_overview, lc)


async def _pillar_detection_coverage(window_hours: int) -> list[Finding]:
    from f0_sectools_core.auth.config import SentinelConfig
    from f0_sentinel_mcp import tools
    from f0_sentinel_mcp.client import SentinelClient
    load_dotenv(".env.sentinel")
    cfg = SentinelConfig.from_env("SENTINEL")
    async with SentinelClient(cfg) as c:
        findings = await tools.get_detection_coverage(c)
    # Unlike every other pillar tool, this one also returns up to 25 per-rule
    # findings alongside the summary. Every CISO pillar is a single headline
    # number, so keep only the summary (the first element) -- the per-rule
    # inventory belongs to the detection-engineer group below, not the
    # executive rollup. Sliced, not indexed, so an (unexpected) empty result
    # comes back as [] rather than raising.
    return findings[:1]


# ── Detection-engineer / threat-hunter factories ─────────────────────
async def _defender_alerts(window_hours: int) -> list[Finding]:
    from f0_defender_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.defender")
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _within_window(
            await tools.list_alerts(gc, severity_min="medium", limit=15), window_hours,
        )


async def _defender_incidents(window_hours: int) -> list[Finding]:
    from f0_defender_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.defender")
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _within_window(
            await tools.list_incidents(gc, severity_min="medium", limit=10), window_hours,
        )


async def _lc_dr_rules(window_hours: int) -> list[Finding]:
    from f0_limacharlie_mcp import tools
    from f0_limacharlie_mcp.client import LimaCharlieClient
    from f0_sectools_core.auth.config import LimaCharlieConfig
    load_dotenv(".env.limacharlie")
    lc = LimaCharlieClient(LimaCharlieConfig.from_env())
    return await asyncio.to_thread(tools.list_dr_rules, lc, "general", 15)


async def _lc_detections(window_hours: int) -> list[Finding]:
    from f0_limacharlie_mcp import tools
    from f0_limacharlie_mcp.client import LimaCharlieClient
    from f0_sectools_core.auth.config import LimaCharlieConfig
    load_dotenv(".env.limacharlie")
    lc = LimaCharlieClient(LimaCharlieConfig.from_env())
    return await asyncio.to_thread(tools.list_detections, lc, float(window_hours), 15)


async def _sentinel_analytics_rules(window_hours: int) -> list[Finding]:
    from f0_sectools_core.auth.config import SentinelConfig
    from f0_sentinel_mcp import tools
    from f0_sentinel_mcp.client import SentinelClient
    load_dotenv(".env.sentinel")
    cfg = SentinelConfig.from_env("SENTINEL")
    async with SentinelClient(cfg) as c:
        # Full result, including the per-rule findings the CISO pillar above
        # trims away -- the rule inventory is exactly what this persona's
        # report exists to show.
        return await tools.get_detection_coverage(c)


async def _pa_weak_techniques(window_hours: int) -> list[Finding]:
    from f0_projectachilles_mcp import tools
    from f0_projectachilles_mcp.client import ProjectAchillesClient
    from f0_sectools_core.auth.config import ProjectAchillesConfig
    load_dotenv(".env.projectachilles")
    async with ProjectAchillesClient(ProjectAchillesConfig.from_env()) as pa:
        return await tools.get_weak_techniques(pa, days=max(1, window_hours // 24), limit=10)


# ── Security-engineer factories ──────────────────────────────────────
async def _entra_conditional_access(window_hours: int) -> list[Finding]:
    from f0_entra_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.entra")
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        # list_conditional_access_policies has no limit param (it pages unbounded),
        # so bound it here — the report is a human-facing document and every other
        # group is capped.
        return (await tools.list_conditional_access_policies(gc))[:10]


async def _entra_privileged_roles(window_hours: int) -> list[Finding]:
    from f0_entra_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.entra")
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        return await tools.list_privileged_role_assignments(gc, limit=10)


async def _entra_risky_users(window_hours: int) -> list[Finding]:
    from f0_entra_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.entra")
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        return await tools.list_risky_users(gc, limit=10)


async def _intune_stale_devices(window_hours: int) -> list[Finding]:
    from f0_intune_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.intune")
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        # Deliberately NOT window_hours: "stale" is defined by the tool's own
        # 30-day-default threshold, not by the report's lookback window.
        return await tools.list_stale_devices(gc, limit=10)


async def _tenable_top_vulns(window_hours: int) -> list[Finding]:
    from f0_sectools_core.auth.config import TenableConfig
    from f0_tenable_mcp import tools
    from f0_tenable_mcp.client import TenableClient
    load_dotenv(".env.tenable")
    async with TenableClient(TenableConfig.from_env()) as tio:
        return await tools.list_top_vulnerabilities(tio, limit=10)


# persona -> {group label: factory}. Patched in tests.
# The CISO map is the seven-pillar rollup; operational personas gather their own
# working data (see docs/superpowers/specs/2026-07-25-report-persona-gathering-design.md).
GATHER_MAP: dict[str, dict[str, Callable[[int], Awaitable[list[Finding]]]]] = {
    "ciso": {
        "config_hardening": _pillar_config_hardening,
        "attack_validation": _pillar_attack_validation,
        "vulnerability_exposure": _pillar_vuln_exposure,
        "device_compliance": _pillar_device_compliance,
        "data_risk": _pillar_data_risk,
        "endpoint_coverage": _pillar_endpoint_coverage,
        "detection_coverage": _pillar_detection_coverage,
    },
    "detection_engineer": {
        "alerts_mitre": _defender_alerts,
        "incidents": _defender_incidents,
        "detection_rules": _lc_dr_rules,
        "endpoint_detections": _lc_detections,
        "weak_techniques": _pa_weak_techniques,
        "analytics_rules": _sentinel_analytics_rules,
    },
    "threat_hunter": {
        "incidents": _defender_incidents,
        "alerts_mitre": _defender_alerts,
        "endpoint_detections": _lc_detections,
        "endpoint_coverage": _pillar_endpoint_coverage,
    },
    "security_engineer": {
        "config_hardening": _pillar_config_hardening,
        "conditional_access": _entra_conditional_access,
        "privileged_roles": _entra_privileged_roles,
        "risky_users": _entra_risky_users,
        "device_compliance": _pillar_device_compliance,
        "stale_devices": _intune_stale_devices,
        "vulnerability_exposure": _pillar_vuln_exposure,
        "top_vulnerabilities": _tenable_top_vulns,
    },
}


_SEV_ORDER = ("critical", "high", "medium", "low", "info")
# `info` is `clear` (muted), NOT `strong` (green). A finding scored `low` has been
# assessed and judged fine — green states that. `info` carries no risk judgment at
# all; it is a fact. Painting a fact green asserts good news the data never
# claimed, and on a real tenant it did exactly that: "0 unresolved DLP alerts"
# rendered green while the report's own narrative warned that zero is ambiguous
# until you confirm policies are deployed, and "114 online" rendered green for a
# fleet whose own detail line read "1178 dormant sleepers".
#
# This is the same call _count_metric already makes for an empty operational
# group, for the same reason — the two paths now agree.
_SEV_STATE = {
    "critical": "exposure", "high": "needs-work", "medium": "needs-work",
    "low": "strong", "info": "clear",
}


def _metric_from(pillar: str, findings: list[Finding]) -> MetricCard:
    real = [f for f in findings if not is_not_assessed(f)]
    if not real:
        return MetricCard(pillar, "—", "not-assessed")
    f = real[0]
    headline = next((e.value for e in f.evidence if e.key == "headline"), "")
    if not headline:
        # A real finding without a headline is anomalous (e.g. an unclassified
        # platform-error finding not caught by is_not_assessed) — render it
        # unquantified rather than a truncated title at tile size or a misleading
        # "strong" state. The full title still shows in the detail line.
        return MetricCard(pillar, "—", "not-assessed", detail=f.title)
    return MetricCard(pillar, headline, _SEV_STATE[f.severity.value], detail=f.title)


def _count_metric(group: str, findings: list[Finding]) -> MetricCard:
    """An at-a-glance tile for an operational group: how many findings it produced.

    An empty group is `clear`, not `strong` — "0 endpoint detections" is not good
    news when most sensors are dormant, and a green tile would contradict the
    narrative. A group whose findings are all degradations is `not-assessed`.
    """
    real = [f for f in findings if not is_not_assessed(f)]
    if not findings:
        return MetricCard(group, "0", "clear", detail="nothing_in_window")
    if not real:
        return MetricCard(group, "—", "not-assessed")
    counts = {sev: sum(1 for f in real if f.severity.value == sev) for sev in _SEV_ORDER}
    worst = next((s for s in _SEV_ORDER if counts[s]), "info")
    breakdown = tuple((s, counts[s]) for s in _SEV_ORDER if counts[s])
    return MetricCard(group, str(len(real)), _SEV_STATE[worst], severity_counts=breakdown)


async def _run_group(group: str, factory, window_hours: int) -> tuple[str, list[Finding]]:
    try:
        findings = await factory(window_hours)
    except Exception as exc:  # noqa: BLE001 — any platform failure degrades, never aborts
        return group, [_degraded(group, str(exc))]
    # The report is a shared artifact — apply the same structural redaction every
    # server's _render does (plus evidence-key-aware blanking), not just the
    # value-pattern net the emitters use. See core.redaction.redact.redact_finding.
    return group, [redact_finding(f) for f in findings]


async def gather(persona: str, window_hours: int) -> tuple[list[Finding], ScopeMeta]:
    key = persona.replace("-", "_")
    groups = GATHER_MAP.get(key)
    if groups is None:
        raise ValueError(f"Unknown persona '{persona}'. Valid: {', '.join(sorted(GATHER_MAP))}")
    results = await asyncio.gather(*[
        _run_group(group, factory, window_hours) for group, factory in groups.items()
    ])
    findings: list[Finding] = []
    assessed: list[str] = []
    not_assessed: list[str] = []
    metrics: list[MetricCard] = []
    platforms: list[str] = []
    real_count = 0
    for group, group_findings in results:
        findings.extend(group_findings)
        healthy = [f for f in group_findings if not is_not_assessed(f)]
        real_count += len(healthy)
        # A group that ran and returned nothing is ASSESSED with nothing to report
        # (no risky users is good news); only a group whose every finding is a
        # degradation is genuinely dark. CISO groups always return one finding, so
        # this is byte-identical for the CISO report.
        if group_findings and not healthy:
            not_assessed.append(group)
        else:
            assessed.append(group)
        # Provenance counts real platforms, not group labels — derive it from the
        # findings' own `source` field (a degraded group contributes no source
        # here; it's still visible via not_assessed).
        for f in healthy:
            if f.source not in platforms:
                platforms.append(f.source)
        # CISO groups are one headline posture finding each (a percentage/score);
        # operational groups are lists, so their tile is the count.
        if key == "ciso":
            metrics.append(_metric_from(group, group_findings))
        else:
            metrics.append(_count_metric(group, group_findings))
    meta = ScopeMeta(
        generated_at="",  # stamped by the CLI
        tenant_label="",
        window_label=(
            f"Trailing {window_hours // 24} days"
            if window_hours >= 24
            else f"Trailing {window_hours}h"
        ),
        platforms_queried=platforms,
        findings_count=real_count,
        assessed=assessed,
        not_assessed=not_assessed,
        pillar_metrics=metrics,
    )
    return findings, meta
