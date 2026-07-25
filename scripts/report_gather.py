"""Platform-aware finding gather for reports. Lives in scripts/ (may import
servers/*); core/reports stays platform-free. Each persona gathers its own
groups (GATHER_MAP) — the CISO the six-pillar rollup, the operational personas
their working data. Each factory mirrors the matching live_smoke_*.py client
construction. A platform that raises degrades to a posture finding so the report
still generates (graceful-partial)."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from dotenv import load_dotenv
from f0_sectools_core.redaction.redact import redact_finding, redact_text
from f0_sectools_core.reports.content import MetricCard, ScopeMeta
from f0_sectools_core.reports.sections import is_not_assessed
from f0_sectools_core.schema.findings import Evidence, Finding, FindingType, Severity


def _degraded(group: str, detail: str) -> Finding:
    return Finding(
        source=group.lower().replace(" ", "_"),
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"{group} not configured — not assessed",
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


# ── Detection-engineer / threat-hunter factories ─────────────────────
async def _defender_alerts(window_hours: int) -> list[Finding]:
    from f0_defender_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.defender")
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return await tools.list_alerts(gc, severity_min="medium", limit=15)


async def _defender_incidents(window_hours: int) -> list[Finding]:
    from f0_defender_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.defender")
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return await tools.list_incidents(gc, severity_min="medium", limit=10)


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


async def _pa_weak_techniques(window_hours: int) -> list[Finding]:
    from f0_projectachilles_mcp import tools
    from f0_projectachilles_mcp.client import ProjectAchillesClient
    from f0_sectools_core.auth.config import ProjectAchillesConfig
    load_dotenv(".env.projectachilles")
    async with ProjectAchillesClient(ProjectAchillesConfig.from_env()) as pa:
        return await tools.get_weak_techniques(pa, limit=10)


# ── Security-engineer factories ──────────────────────────────────────
async def _entra_conditional_access(window_hours: int) -> list[Finding]:
    from f0_entra_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.entra")
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        return await tools.list_conditional_access_policies(gc)


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
        return await tools.list_stale_devices(gc, limit=10)


async def _tenable_top_vulns(window_hours: int) -> list[Finding]:
    from f0_sectools_core.auth.config import TenableConfig
    from f0_tenable_mcp import tools
    from f0_tenable_mcp.client import TenableClient
    load_dotenv(".env.tenable")
    async with TenableClient(TenableConfig.from_env()) as tio:
        return await tools.list_top_vulnerabilities(tio, limit=10)


# persona -> {group label: factory}. Patched in tests.
# The CISO map is the six-pillar rollup; operational personas gather their own
# working data (see docs/superpowers/specs/2026-07-25-report-persona-gathering-design.md).
GATHER_MAP: dict[str, dict[str, Callable[[int], Awaitable[list[Finding]]]]] = {
    "ciso": {
        "Config hardening": _pillar_config_hardening,
        "Attack validation": _pillar_attack_validation,
        "Vulnerability exposure": _pillar_vuln_exposure,
        "Device compliance": _pillar_device_compliance,
        "Data risk": _pillar_data_risk,
        "Endpoint coverage": _pillar_endpoint_coverage,
    },
    "detection_engineer": {
        "Alerts (MITRE)": _defender_alerts,
        "Incidents": _defender_incidents,
        "Detection rules": _lc_dr_rules,
        "Endpoint detections": _lc_detections,
        "Weak techniques": _pa_weak_techniques,
    },
    "threat_hunter": {
        "Incidents": _defender_incidents,
        "Alerts (MITRE)": _defender_alerts,
        "Endpoint detections": _lc_detections,
        "Endpoint coverage": _pillar_endpoint_coverage,
    },
    "security_engineer": {
        "Config hardening": _pillar_config_hardening,
        "Conditional access": _entra_conditional_access,
        "Privileged roles": _entra_privileged_roles,
        "Risky users": _entra_risky_users,
        "Device compliance": _pillar_device_compliance,
        "Stale devices": _intune_stale_devices,
        "Vulnerability exposure": _pillar_vuln_exposure,
        "Top vulnerabilities": _tenable_top_vulns,
    },
}


def _metric_from(pillar: str, findings: list[Finding]) -> MetricCard:
    real = [f for f in findings if not is_not_assessed(f)]
    if not real:
        return MetricCard(pillar, "not assessed", "not-assessed")
    f = real[0]
    headline = next((e.value for e in f.evidence if e.key == "headline"), "")
    if not headline:
        # A real finding without a headline is anomalous (e.g. an unclassified
        # platform-error finding not caught by is_not_assessed) — render it
        # unquantified rather than a truncated title at tile size or a misleading
        # "strong" state. The full title still shows in the detail line.
        return MetricCard(pillar, "—", "not-assessed", detail=f.title)
    state = {"critical": "exposure", "high": "needs-work", "medium": "needs-work"}.get(
        f.severity.value, "strong")
    return MetricCard(pillar, headline, state, detail=f.title)


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
    for group, group_findings in results:
        findings.extend(group_findings)
        healthy = [f for f in group_findings if not is_not_assessed(f)]
        if healthy:
            assessed.append(group)
        else:
            not_assessed.append(group)
        # Tiles are an executive-tier device: a CISO group is one headline
        # posture finding, an operational group is a list of alerts/detections.
        if key == "ciso":
            metrics.append(_metric_from(group, group_findings))
    meta = ScopeMeta(
        generated_at="",  # stamped by the CLI
        tenant_label="",
        window_label=(
            f"Trailing {window_hours // 24} days"
            if window_hours >= 24
            else f"Trailing {window_hours}h"
        ),
        platforms_queried=[g.lower().replace(" ", "_") for g in groups],
        findings_count=len(findings),
        assessed=assessed,
        not_assessed=not_assessed,
        pillar_metrics=metrics,
    )
    return findings, meta
