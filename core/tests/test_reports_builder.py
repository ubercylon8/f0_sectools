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
        pillar_metrics=[MetricCard("Config hardening", "62%", "needs-work")],
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
