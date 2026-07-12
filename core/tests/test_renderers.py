"""Contract tests for core/renderers — deterministic Finding -> Markdown text."""
from __future__ import annotations

from f0_sectools_core.redaction.patterns import REDACTED
from f0_sectools_core.renderers.base import Renderer
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
