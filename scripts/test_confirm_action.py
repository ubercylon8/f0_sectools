"""Offline tests for the confirm_action CLI helpers (no TTY, tmp dirs only)."""
from __future__ import annotations

import json

from f0_sectools_core.gating.actions import ApprovalStore, AuditLog

from scripts.confirm_action import approve_one, deny_one, resolve_action, watch_once


def _stores(tmp_path):
    return (
        ApprovalStore(str(tmp_path / "gating")),
        AuditLog(str(tmp_path / "gating" / "audit.log")),
    )


def test_resolve_action_adds_platform_prefix_once():
    assert resolve_action("run_test", "projectachilles") == "projectachilles.run_test"
    assert resolve_action("defender.isolate_host", "defender") == "defender.isolate_host"


def test_approve_one_grants_and_audits(tmp_path):
    store, audit = _stores(tmp_path)
    store.record_request("projectachilles.run_test", "uuid@host")
    approve_one(store, audit, "projectachilles.run_test", "uuid@host", ttl_s=900)
    assert store.has_approval("projectachilles.run_test", "uuid@host") is True
    assert store.list_pending() == []
    entry = json.loads(audit.path.read_text().strip())
    assert entry["method"] == "approved"


def test_deny_one_removes_and_audits(tmp_path):
    store, audit = _stores(tmp_path)
    store.record_request("a.b", "t")
    deny_one(store, audit, "a.b", "t")
    assert store.list_pending() == []
    assert store.has_approval("a.b", "t") is False
    entry = json.loads(audit.path.read_text().strip())
    assert entry["method"] == "denied"


def test_watch_once_approves_on_y_and_denies_on_n(tmp_path):
    store, audit = _stores(tmp_path)
    store.record_request("a.b", "t1")
    store.record_request("a.b", "t2")
    answers = iter(["y", "n"])
    handled = watch_once(store, audit, ask=lambda prompt: next(answers))
    assert handled == 2
    granted = [t for t in ("t1", "t2") if store.has_approval("a.b", t)]
    assert len(granted) == 1
    assert store.list_pending() == []


def test_watch_once_no_pending_is_quiet(tmp_path):
    store, audit = _stores(tmp_path)
    assert watch_once(store, audit, ask=lambda prompt: "y") == 0
