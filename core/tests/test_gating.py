import json

import pytest

from f0_sectools_core.gating.actions import AuditLog, GatedAction, GateDenied


def test_denied_when_disabled(tmp_path):
    g = GatedAction("isolate_host", enabled=False, audit=AuditLog(str(tmp_path / "a.log")))
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token="abc", run=lambda: "done")


def test_denied_without_token(tmp_path):
    g = GatedAction("isolate_host", enabled=True, audit=AuditLog(str(tmp_path / "a.log")))
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token=None, run=lambda: "done")


def test_executes_and_audits(tmp_path):
    log = tmp_path / "a.log"
    g = GatedAction("isolate_host", enabled=True, audit=AuditLog(str(log)))
    result = g.execute(target="web-01", actor="james", token="confirm-123", run=lambda: "isolated")
    assert result == "isolated"
    entry = json.loads(log.read_text().strip())
    assert entry["action"] == "isolate_host"
    assert entry["target"] == "web-01"
    assert entry["token"] == "confirm-123"
