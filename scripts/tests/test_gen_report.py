import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/ importable
import report_gather  # noqa: E402
from f0_sectools_core.reports.content import ScopeMeta  # noqa: E402
from f0_sectools_core.schema.findings import Finding, FindingType, Severity  # noqa: E402


def test_gather_degrades_when_platform_unconfigured(monkeypatch):
    # Force every pillar factory to raise (no creds) → all not-assessed, still returns.
    async def boom(window_hours):
        raise ValueError("Missing required environment variables: DEFENDER_TENANT_ID")

    monkeypatch.setattr(report_gather, "_PILLAR_FACTORIES",
                        {"Config hardening": boom, "Vulnerability exposure": boom})
    findings, meta = asyncio.run(report_gather.gather("ciso", 168))
    assert isinstance(meta, ScopeMeta)
    assert set(meta.not_assessed) >= {"Config hardening", "Vulnerability exposure"}
    assert meta.assessed == []  # nothing came back healthy
    # every dark pillar still produced a posture finding
    assert all(f.finding_type is FindingType.posture for f in findings)
    # the failure cause survives as redacted evidence, not silently dropped
    for f in findings:
        reasons = [e.value for e in f.evidence if e.key == "reason"]
        assert reasons and reasons[0]


def test_gather_collects_healthy_pillar(monkeypatch):
    async def ok(window_hours):
        return [Finding(source="defender", finding_type=FindingType.posture,
                        severity=Severity.info, title="Secure Score: 62%",
                        evidence=[{"key": "secure_score_pct", "value": "62"}])]

    monkeypatch.setattr(report_gather, "_PILLAR_FACTORIES", {"Config hardening": ok})
    findings, meta = asyncio.run(report_gather.gather("ciso", 168))
    assert "Config hardening" in meta.assessed
    assert any("62%" in f.title for f in findings)
