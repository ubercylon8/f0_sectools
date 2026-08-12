import importlib
from pathlib import Path

import pytest
from f0_sectools_core.redaction.redact import redact_obj, redact_text


def test_redacts_bearer_token():
    assert "«redacted»" in redact_text("Authorization: Bearer abc.DEF-123_xyz.longtokenvalue")


def test_redacts_secret_keyed_values():
    out = redact_obj({"client_secret": "s3cr3t-value-here", "host": "web-01"})
    assert out["client_secret"] == "«redacted»"
    assert out["host"] == "web-01"


def test_redacts_nested():
    out = redact_obj({"creds": {"password": "hunter2hunter2"}, "items": ["ok"]})
    assert out["creds"]["password"] == "«redacted»"
    assert out["items"] == ["ok"]


def test_redacts_additional_secret_key_hints():
    # Low-entropy secrets under these keys wouldn't match a value pattern, so the
    # key-hint pass must catch them (private_key/credentials/cookie).
    out = redact_obj({
        "private_key": "abc", "credentials": "u:p", "cookie": "sid=1",
        "host": "web-01", "credentialGuardEnabled": True,
    })
    assert out["private_key"] == "«redacted»"
    assert out["credentials"] == "«redacted»"
    assert out["cookie"] == "«redacted»"
    assert out["host"] == "web-01"
    # `credentials` (not bare `credential`) so informative posture fields survive.
    assert out["credentialGuardEnabled"] is True


def test_redacts_camelcase_secret_keys():
    # Underscore normalization makes multi-word hints catch camelCase too — Graph
    # servers (Entra/Defender/Intune) emit privateKey/clientSecret.
    out = redact_obj({"privateKey": "y", "clientSecret": "z", "host": "web-01"})
    assert out["privateKey"] == "«redacted»"
    assert out["clientSecret"] == "«redacted»"
    assert out["host"] == "web-01"


def test_redact_finding_blanks_secret_hinting_evidence_value():
    # Evidence is a flat {key, value} list, so redact_obj's dict-key check never
    # sees the evidence key name — redact_finding closes that gap. A short,
    # non-token secret under a secret-hinting evidence key must be blanked.
    from f0_sectools_core.redaction.redact import redact_finding
    from f0_sectools_core.schema.findings import (
        Evidence,
        Finding,
        FindingType,
        Severity,
    )

    f = Finding(
        source="defender", finding_type=FindingType.posture, severity=Severity.info,
        title="pillar",
        evidence=[
            Evidence(key="client_secret", value="hunter2pw"),   # secret-hinting key
            Evidence(key="score", value="62"),                  # benign
        ],
    )
    red = redact_finding(f)
    ev = {e.key: e.value for e in red.evidence}
    assert ev["client_secret"] == "«redacted»"
    assert ev["score"] == "62"
    # Original finding is untouched (new Finding returned).
    assert f.evidence[0].value == "hunter2pw"


def test_redact_finding_still_applies_value_patterns():
    # redact_finding must also catch token-shaped values under a benign key
    # (the redact_obj/redact_text pass), not only secret-hinting keys.
    from f0_sectools_core.redaction.redact import redact_finding
    from f0_sectools_core.schema.findings import (
        Evidence,
        Finding,
        FindingType,
        Severity,
    )

    f = Finding(
        source="defender", finding_type=FindingType.alert, severity=Severity.high,
        title="token in evidence",
        evidence=[Evidence(key="note", value="token eyJ0eStuffLongEnoughToMatch1234567")],
    )
    red = redact_finding(f)
    assert "«redacted»" in red.evidence[0].value


# Issue #100: every server's `_render` must use `redact_finding` (not the bare
# `redact_obj`), so the evidence-key-hint pass runs on the live tool-output path
# -- not only on the generated-report path (`core/reports/emit.py`). `_render`
# is a module-private helper with no server-specific behaviour to exercise, so
# this is one parametrised test over every server module rather than nine
# near-identical copies.
_SERVER_RENDER_MODULES = [
    "f0_defender_mcp.server",
    "f0_entra_mcp.server",
    "f0_intune_mcp.server",
    "f0_limacharlie_mcp.server",
    "f0_projectachilles_mcp.server",
    "f0_pa_actions_mcp.server",
    "f0_purview_mcp.server",
    "f0_sentinel_mcp.server",
    "f0_tenable_mcp.server",
]

_SERVERS_DIR = Path(__file__).resolve().parents[2] / "servers"
_DISCOVERED_SERVER_COUNT = len(
    [p for p in _SERVERS_DIR.iterdir() if p.is_dir() and p.name.endswith("-mcp")]
)


def test_server_render_modules_list_is_not_missing_a_server():
    # This list is hand-maintained -- tie its length to the discovered
    # server count so a tenth server added under servers/ can't silently
    # skip this redaction regression test.
    assert len(_SERVER_RENDER_MODULES) == _DISCOVERED_SERVER_COUNT


@pytest.mark.parametrize("module_name", _SERVER_RENDER_MODULES)
def test_server_render_blanks_secret_hinting_evidence_value(module_name):
    from f0_sectools_core.schema.findings import Evidence, Finding, FindingType, Severity

    server = importlib.import_module(module_name)
    f = Finding(
        source="test", finding_type=FindingType.posture, severity=Severity.info,
        title="pillar",
        evidence=[
            Evidence(key="client_secret", value="hunter2pw"),  # secret-hinting key
            Evidence(key="score", value="62"),                  # benign
        ],
    )
    out = server._render([f])
    assert len(out) == 1
    ev = {e["key"]: e["value"] for e in out[0]["evidence"]}
    assert ev["client_secret"] == "«redacted»"
    assert ev["score"] == "62"
