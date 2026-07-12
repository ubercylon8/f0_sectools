"""Contract tests for core/renderers — deterministic Finding -> Markdown text."""
from __future__ import annotations

import pytest
from f0_sectools_core.redaction.patterns import REDACTED
from f0_sectools_core.renderers import render_finding, render_findings
from f0_sectools_core.renderers.base import Persona, Renderer
from f0_sectools_core.renderers.personas import REGISTRY, get_renderer
from f0_sectools_core.schema.findings import (
    Entity,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Reference,
    Severity,
)


def _rich() -> Finding:
    return Finding(
        source="defender",
        finding_type=FindingType.incident,
        severity=Severity.critical,
        title="Ransomware activity on host web-01",
        entity=Entity(kind="host", id="web-01", name="web-01.corp.local"),
        evidence=[Evidence(key="failed_logins", value="142 in 5m")],
        recommended_action=RecommendedAction(
            summary="Isolate host and reset affected credentials",
            gated_action="defender.isolate_host",
            confidence="high",
        ),
        references=[Reference(type="mitre", id="T1486", url="https://attack.mitre.org/techniques/T1486/")],
        observed_at="2026-06-28T10:00:00Z",
    )


def _sparse() -> Finding:
    return Finding(
        source="entra",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title="No risky users detected",
    )


def test_base_severity_tag_is_uppercase():
    assert Renderer()._severity_tag(_rich()) == "CRITICAL"


def test_base_entity_str_handles_none():
    assert Renderer()._entity_str(_sparse()) == "unspecified target"


def test_base_entity_str_with_name():
    assert Renderer()._entity_str(_rich()) == "host: web-01.corp.local (web-01)"


def test_base_render_finding_sparse_does_not_crash_or_show_none():
    out = Renderer().render_finding(_sparse())
    assert out
    assert "None" not in out


def test_base_render_findings_empty_list():
    assert Renderer().render_findings([]) == "No findings."


def test_base_render_finding_redacts_secrets():
    f = _sparse()
    f.evidence = [Evidence(key="note", value="token Bearer abcdef0123456789xyz leaked")]
    out = Renderer().render_finding(f)
    assert REDACTED in out
    assert "abcdef0123456789xyz" not in out


def test_base_render_is_deterministic():
    r = Renderer()
    assert r.render_findings([_rich(), _sparse()]) == r.render_findings([_rich(), _sparse()])


# ── Task 2: persona renderers ────────────────────────────────────────────────


def _mixed() -> list[Finding]:
    return [
        Finding(
            source="defender", finding_type=FindingType.incident, severity=Severity.high,
            title="Suspicious PowerShell", entity=Entity(kind="host", id="pc-9"),
            references=[Reference(type="mitre", id="T1059")],
            observed_at="2026-06-28T12:00:00Z",
        ),
        Finding(
            source="entra", finding_type=FindingType.risk, severity=Severity.critical,
            title="Impossible travel sign-in", entity=Entity(kind="user", id="alice"),
            evidence=[Evidence(key="geo", value="US then RU in 4m")],
            observed_at="2026-06-28T09:00:00Z",  # earlier than the defender one
        ),
        Finding(
            source="limacharlie", finding_type=FindingType.misconfig, severity=Severity.medium,
            title="EDR sensor offline",
            recommended_action=RecommendedAction(summary="Reinstall the sensor on host db-2"),
        ),
    ]


def test_registry_has_all_five_personas():
    assert set(REGISTRY) == set(Persona)


def test_get_renderer_coerces_str():
    assert get_renderer("ciso") is REGISTRY[Persona.ciso]


def test_get_renderer_unknown_raises_valueerror():
    with pytest.raises(ValueError, match="Unknown persona"):
        get_renderer("cto")


def test_ciso_list_has_counts_and_omits_raw_evidence():
    out = get_renderer(Persona.ciso).render_findings(_mixed())
    assert "1 critical" in out
    assert "US then RU in 4m" not in out  # CISO never dumps raw evidence


def test_threat_hunter_list_is_timeline_ordered():
    out = get_renderer(Persona.threat_hunter).render_findings(_mixed())
    # the 09:00 sign-in must appear before the 12:00 PowerShell finding
    assert out.index("2026-06-28T09:00:00Z") < out.index("2026-06-28T12:00:00Z")


def test_detection_engineer_flags_unmapped_and_shows_technique():
    out = get_renderer(Persona.detection_engineer).render_findings(_mixed())
    assert "unmapped" in out          # the entra + limacharlie findings have no mitre ref
    assert "T1059" in out             # the defender finding is mapped


def test_soc_analyst_single_shows_next_step_and_gated_action():
    out = get_renderer(Persona.soc_analyst).render_finding(_rich())
    assert "Next step:" in out
    assert "defender.isolate_host" in out


def test_security_engineer_list_is_a_checklist():
    out = get_renderer(Persona.security_engineer).render_findings(_mixed())
    assert "- [ ]" in out


# ── Task 3: public API ────────────────────────────────────────────────────────


def test_public_render_finding_default_persona_is_soc_analyst():
    # default persona shows the SOC-analyst "Next step:" framing
    assert "Next step:" in render_finding(_rich())


def test_public_render_findings_accepts_str_persona():
    out = render_findings(_mixed(), "ciso")
    assert "Security posture rollup" in out


def test_public_render_findings_unknown_persona_raises():
    with pytest.raises(ValueError, match="Unknown persona"):
        render_findings(_mixed(), "nope")


# ── Fix 1: per-persona robustness ─────────────────────────────────────────────


@pytest.mark.parametrize("persona", [p.value for p in Persona])
def test_render_finding_sparse_is_robust_for_every_persona(persona):
    out = render_finding(_sparse(), persona)
    assert out
    assert "None" not in out


@pytest.mark.parametrize("persona", [p.value for p in Persona])
def test_render_findings_mixed_is_robust_for_every_persona(persona):
    out = render_findings(_mixed(), persona)
    assert out
    assert "None" not in out


# ── Fix 2: detection_engineer single-finding body ─────────────────────────────


def test_detection_engineer_single_shows_technique_and_source():
    out = render_finding(_rich(), "detection_engineer")
    assert "T1486" in out
    assert "defender" in out


def test_detection_engineer_single_sparse_is_unmapped():
    out = render_finding(_sparse(), "detection_engineer")
    assert "unmapped" in out


# ── Fix 3: soc_analyst tie-break by observed_at within equal severity ─────────


def test_soc_analyst_list_breaks_severity_ties_by_time():
    earlier = Finding(
        source="defender", finding_type=FindingType.incident, severity=Severity.high,
        title="Earlier high-severity finding",
        observed_at="2026-06-28T08:00:00Z",
    )
    later = Finding(
        source="defender", finding_type=FindingType.incident, severity=Severity.high,
        title="Later high-severity finding",
        observed_at="2026-06-28T14:00:00Z",
    )
    out = get_renderer(Persona.soc_analyst).render_findings([later, earlier])
    assert out.index("Earlier high-severity finding") < out.index("Later high-severity finding")
