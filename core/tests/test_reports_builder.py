import json
from pathlib import Path

import pytest
from f0_sectools_core.reports import build_report
from f0_sectools_core.reports.content import MetricCard, ScopeMeta
from f0_sectools_core.schema.findings import Finding

FIX = Path(__file__).parent / "fixtures" / "reports"


def _findings() -> list[Finding]:
    data = json.loads((FIX / "findings_ciso.json").read_text())
    return [Finding.model_validate(d) for d in data]


def _scope() -> ScopeMeta:
    return ScopeMeta(
        generated_at="2026-07-24 14:22", tenant_label="Contoso",
        window_label="Trailing 7 days",
        platforms_queried=[
            "defender", "tenable", "intune", "purview", "projectachilles", "limacharlie",
        ],
        findings_count=3, assessed=["Config hardening", "Vulnerability exposure"],
        not_assessed=["Insider risk (not licensed)"],
        pillar_metrics=[MetricCard("Config hardening", "62%", "needs-work",
                                    detail="Microsoft Secure Score 1130/1816")],
    )


def test_ciso_en_report_structure():
    narrative = (FIX / "narrative_ciso_en.md").read_text()
    out = build_report("ciso", "en", narrative, _findings(), _scope())
    md = out.markdown
    # ordered executive section headings present
    for heading in ["Executive summary", "Posture at a glance", "Top risks",
                    "Scope & coverage", "Open questions", "Provenance"]:
        assert f"## {heading}" in md, heading
    assert "62%" in md
    assert "Not assessed: Insider risk (not licensed)" in md
    assert "2026-07-24 14:22" in md
    assert "fastest single reduction" in md  # risk_framing prose rendered in Top risks
    assert out.html.startswith("<!doctype html>")


def test_ciso_es_uses_spanish_labels():
    narrative = (FIX / "narrative_ciso_es.md").read_text()
    out = build_report("ciso", "es", narrative, _findings(), _scope())
    assert "## Resumen ejecutivo" in out.markdown
    assert "## Preguntas abiertas" in out.markdown
    assert "No evaluado:" in out.markdown


def test_hyphenated_persona_accepted():
    out = build_report("threat-hunter", "en", "## Executive Summary\nHi.\n", _findings(), _scope())
    assert "Prepared for Threat Hunting" in out.markdown


def test_golden_ciso_en_frozen():
    narrative = (FIX / "narrative_ciso_en.md").read_text()
    out = build_report("ciso", "en", narrative, _findings(), _scope())
    expected = (FIX / "golden_ciso_en.md").read_text()
    assert out.markdown == expected


def test_unknown_persona_raises_value_error():
    with pytest.raises(ValueError):
        build_report("nonsense", "en", "", [], _scope())


def _detection_findings() -> list[Finding]:
    data = json.loads((FIX / "findings_detection.json").read_text())
    return [Finding.model_validate(d) for d in data]


def _op_scope() -> ScopeMeta:
    return ScopeMeta(
        generated_at="2026-07-24 14:22", tenant_label="Contoso",
        window_label="Trailing 7 days", platforms_queried=["defender", "limacharlie"],
        findings_count=2, assessed=["Detections"], not_assessed=[],
    )


def test_operational_report_renders_evidence_and_mitre():
    narrative = (FIX / "narrative_detection_en.md").read_text()
    out = build_report("detection-engineer", "en", narrative, _detection_findings(), _op_scope())
    md = out.markdown
    assert "ATT&CK: T1059" in md
    assert "ATT&CK: T1071, T1571" in md          # multiple techniques joined
    assert "device: web-01.corp.local" in md      # evidence rendered
    assert "account: CORP\\jsmith" in md


def test_ciso_executive_tier_suppresses_mitre_and_evidence_bullets():
    # Run MITRE-bearing, multi-evidence findings (normally rendered dense under
    # the operational tier) through the CISO persona instead. If a regression
    # ever routed CISO through the operational finding_table path, these
    # findings' T1059/ATT&CK/evidence sub-bullets would leak into the output —
    # unlike _findings() (findings_ciso.json), which carries no MITRE refs and
    # so can't catch that regression.
    narrative = (FIX / "narrative_ciso_en.md").read_text()
    out = build_report("ciso", "en", narrative, _detection_findings(), _scope())
    md = out.markdown
    assert "ATT&CK" not in md                     # executive tier stays compact
    assert "T1059" not in md                      # technique id must not leak either
    assert "\n  - account:" not in md              # no evidence sub-bullet lines


def test_golden_detection_en_frozen():
    narrative = (FIX / "narrative_detection_en.md").read_text()
    out = build_report("detection-engineer", "en", narrative, _detection_findings(), _op_scope())
    assert out.markdown == (FIX / "golden_detection_en.md").read_text()


def test_each_persona_gets_its_own_title():
    narrative = "## Executive Summary\nHi.\n"
    titles = {
        p: build_report(p, "en", narrative, [], _scope()).markdown.splitlines()[0]
        for p in ("ciso", "detection-engineer", "threat-hunter", "security-engineer")
    }
    assert titles["ciso"] == "# Executive Risk Briefing"
    assert titles["detection-engineer"] == "# Detection Coverage Report"
    assert titles["threat-hunter"] == "# Threat Hunting Report"
    assert titles["security-engineer"] == "# Security Hardening Report"
    assert len(set(titles.values())) == 4  # all distinct


def test_spanish_report_translates_tiles_and_coverage():
    from f0_sectools_core.reports.content import MetricCard, ScopeMeta

    meta = ScopeMeta(
        generated_at="2026-07-24 14:22", tenant_label="Contoso",
        window_label="Trailing 7 days", platforms_queried=["defender"],
        findings_count=1, assessed=["config_hardening"], not_assessed=["data_risk"],
        pillar_metrics=[MetricCard("config_hardening", "90%", "needs-work",
                                   detail="Microsoft Secure Score")],
    )
    md = build_report("ciso", "es", "## Resumen Ejecutivo\nHola.\n", [], meta).markdown
    # group ids and state words render in Spanish
    assert "Endurecimiento de configuración" in md
    assert "requiere atención" in md
    assert "Riesgo de datos" in md            # the not-assessed coverage entry
    # ...and the raw identifiers never leak
    assert "config_hardening" not in md
    assert "needs-work" not in md


def test_english_report_renders_group_ids_as_todays_labels():
    from f0_sectools_core.reports.content import MetricCard, ScopeMeta

    meta = ScopeMeta(
        generated_at="2026-07-24 14:22", tenant_label="Contoso",
        window_label="Trailing 7 days", platforms_queried=["defender"],
        findings_count=1, assessed=["config_hardening"], not_assessed=[],
        pillar_metrics=[MetricCard("config_hardening", "90%", "needs-work")],
    )
    md = build_report("ciso", "en", "## Executive Summary\nHi.\n", [], meta).markdown
    assert "Config hardening" in md          # identical to today's output
    assert "needs work" in md
