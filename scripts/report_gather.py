"""Platform-aware finding gather for reports. Lives in scripts/ (may import
servers/*); core/reports stays platform-free. Each pillar factory mirrors the
matching live_smoke_*.py client construction. A platform that raises degrades to
a posture finding so the report still generates (graceful-partial)."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from dotenv import load_dotenv
from f0_sectools_core.redaction.redact import redact_finding, redact_text
from f0_sectools_core.reports.content import MetricCard, ScopeMeta
from f0_sectools_core.reports.sections import is_not_assessed
from f0_sectools_core.schema.findings import Evidence, Finding, FindingType, Severity


def _degraded(pillar: str, detail: str) -> Finding:
    return Finding(
        source=pillar.lower().replace(" ", "_"),
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"{pillar} not configured — pillar not assessed",
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


# pillar label -> factory. Patched in tests.
_PILLAR_FACTORIES: dict[str, Callable[[int], Awaitable[list[Finding]]]] = {
    "Config hardening": _pillar_config_hardening,
    "Attack validation": _pillar_attack_validation,
    "Vulnerability exposure": _pillar_vuln_exposure,
    "Device compliance": _pillar_device_compliance,
    "Data risk": _pillar_data_risk,
    "Endpoint coverage": _pillar_endpoint_coverage,
}

# Map a pillar's healthy finding to a big-number MetricCard. Best-effort: reads a
# conventional evidence key, falls back to the finding title.
_PILLAR_METRIC_KEY = {
    "Config hardening": "secure_score_pct",
    "Attack validation": "defense_score",
    "Vulnerability exposure": "critical_count",
    "Device compliance": "compliant_pct",
    "Data risk": "alert_count",
    "Endpoint coverage": "online_sensors",
}


def _metric_from(pillar: str, findings: list[Finding]) -> MetricCard:
    real = [f for f in findings if not is_not_assessed(f)]
    if not real:
        return MetricCard(pillar, "not assessed", "not-assessed")
    f = real[0]
    key = _PILLAR_METRIC_KEY.get(pillar, "")
    value = next((e.value for e in f.evidence if e.key == key), f.title)
    state = {"critical": "exposure", "high": "needs-work", "medium": "needs-work"}.get(
        f.severity.value, "strong")
    return MetricCard(pillar, value, state)


async def _run_pillar(pillar: str, factory, window_hours: int) -> tuple[str, list[Finding]]:
    try:
        findings = await factory(window_hours)
    except Exception as exc:  # noqa: BLE001 — any platform failure degrades, never aborts
        return pillar, [_degraded(pillar, str(exc))]
    # The report is a shared artifact — apply the same structural redaction every
    # server's _render does (plus evidence-key-aware blanking), not just the
    # value-pattern net the emitters use. See core.redaction.redact.redact_finding.
    return pillar, [redact_finding(f) for f in findings]


async def gather(persona: str, window_hours: int) -> tuple[list[Finding], ScopeMeta]:
    # v1: all personas gather the six pillars (shared engine); operational personas
    # additionally could gather detail tools — extend GATHER_MAP later.
    results = await asyncio.gather(*[
        _run_pillar(pillar, factory, window_hours)
        for pillar, factory in _PILLAR_FACTORIES.items()
    ])
    findings: list[Finding] = []
    assessed: list[str] = []
    not_assessed: list[str] = []
    metrics: list[MetricCard] = []
    for pillar, pillar_findings in results:
        findings.extend(pillar_findings)
        healthy = [f for f in pillar_findings if not is_not_assessed(f)]
        if healthy:
            assessed.append(pillar)
        else:
            not_assessed.append(pillar)
        metrics.append(_metric_from(pillar, pillar_findings))
    meta = ScopeMeta(
        generated_at="",  # stamped by the CLI
        tenant_label="",
        window_label=(
            f"Trailing {window_hours // 24} days"
            if window_hours >= 24
            else f"Trailing {window_hours}h"
        ),
        platforms_queried=[p.lower().replace(" ", "_") for p in _PILLAR_FACTORIES],
        findings_count=len(findings),
        assessed=assessed,
        not_assessed=not_assessed,
        pillar_metrics=metrics,
    )
    return findings, meta
