import json
from pathlib import Path

import pytest
from f0_sectools_core.gating.actions import (
    ApprovalStore,
    AuditLog,
    GatedAction,
    GateDenied,
    TokenStore,
    gating_dir,
)


def _gate(tmp_path, enabled):
    return GatedAction(
        "defender.isolate_host",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "a.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
        approvals=ApprovalStore(str(tmp_path / "gating")),
    )


# ── TokenStore lifecycle ──────────────────────────────────────────────
def test_token_issue_then_consume_succeeds_once(tmp_path):
    store = TokenStore(str(tmp_path / "pending"))
    tok = store.issue("defender.isolate_host", "web-01")
    assert store.consume("defender.isolate_host", "web-01", tok) is True
    # single-use: second consume fails
    assert store.consume("defender.isolate_host", "web-01", tok) is False


def test_token_rejected_for_wrong_target(tmp_path):
    store = TokenStore(str(tmp_path / "pending"))
    tok = store.issue("defender.isolate_host", "web-01")
    assert store.consume("defender.isolate_host", "web-02", tok) is False


def test_wrong_target_attempt_burns_token(tmp_path):
    # A consume attempt against the wrong target must still burn the token,
    # so it cannot then be replayed against the correct target.
    store = TokenStore(str(tmp_path / "pending"))
    tok = store.issue("defender.isolate_host", "web-01")
    assert store.consume("defender.isolate_host", "web-99", tok) is False  # wrong target
    assert store.consume("defender.isolate_host", "web-01", tok) is False  # now dead


def test_token_rejected_for_wrong_action(tmp_path):
    store = TokenStore(str(tmp_path / "pending"))
    tok = store.issue("defender.isolate_host", "web-01")
    assert store.consume("defender.release_host", "web-01", tok) is False


def test_expired_token_rejected(tmp_path):
    store = TokenStore(str(tmp_path / "pending"))
    tok = store.issue("defender.isolate_host", "web-01", ttl_s=-1)  # already expired
    assert store.consume("defender.isolate_host", "web-01", tok) is False


def test_expired_records_are_swept(tmp_path):
    store = TokenStore(str(tmp_path / "pending"))
    store.issue("defender.isolate_host", "web-01", ttl_s=-1)  # already expired
    pending_dir = tmp_path / "pending"
    assert len(list(pending_dir.glob("*.json"))) == 1
    # Issuing again should sweep the expired record before writing the new one.
    store.issue("defender.isolate_host", "web-02")
    assert len(list(pending_dir.glob("*.json"))) == 1


def test_token_consume_lost_claim_returns_false(tmp_path):
    # Simulates a lost race: the record file vanishes (e.g. a concurrent
    # claimant) between the is_file() check and the atomic unlink.
    store = TokenStore(str(tmp_path / "pending"))
    tok = store.issue("defender.isolate_host", "web-01")
    record_path = store.dir / f"{store._hash(tok)}.json"
    record_path.unlink()
    assert store.consume("defender.isolate_host", "web-01", tok) is False


def test_only_hash_persisted_never_plaintext(tmp_path):
    store = TokenStore(str(tmp_path / "pending"))
    tok = store.issue("defender.isolate_host", "web-01")
    on_disk = (tmp_path / "pending").read_text() if (tmp_path / "pending").is_file() else ""
    for f in (tmp_path / "pending").glob("*"):
        on_disk += f.read_text() + f.name
    assert tok not in on_disk


# ── GatedAction gate ──────────────────────────────────────────────────
def test_denied_when_disabled(tmp_path):
    g = _gate(tmp_path, enabled=False)
    tok = g.token_store.issue("defender.isolate_host", "web-01")
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token=tok, run=lambda: "done")


def test_denied_without_token(tmp_path):
    g = _gate(tmp_path, enabled=True)
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token="", run=lambda: "done")


def test_denied_with_invalid_token(tmp_path):
    g = _gate(tmp_path, enabled=True)
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token="not-a-real-token", run=lambda: "done")


def test_executes_and_audits(tmp_path):
    log = tmp_path / "a.log"
    g = GatedAction(
        "defender.isolate_host",
        enabled=True,
        audit=AuditLog(str(log)),
        token_store=TokenStore(str(tmp_path / "pending")),
    )
    tok = g.token_store.issue("defender.isolate_host", "web-01")
    result = g.execute(target="web-01", actor="james", token=tok, run=lambda: "isolated")
    assert result == "isolated"
    entry = json.loads(log.read_text().strip())
    assert entry["action"] == "defender.isolate_host"
    assert entry["target"] == "web-01"
    assert tok not in log.read_text()  # plaintext token must never be persisted


@pytest.mark.asyncio
async def test_execute_async_runs_and_audits(tmp_path):
    log = tmp_path / "a.log"
    g = GatedAction(
        "defender.isolate_host",
        enabled=True,
        audit=AuditLog(str(log)),
        token_store=TokenStore(str(tmp_path / "pending")),
    )
    tok = g.token_store.issue("defender.isolate_host", "web-01")

    async def _run():
        return {"id": "action-1"}

    result = await g.execute_async(target="web-01", actor="james", token=tok, run=_run)
    assert result == {"id": "action-1"}
    assert json.loads(log.read_text().strip())["action"] == "defender.isolate_host"


@pytest.mark.asyncio
async def test_execute_async_denied_without_token(tmp_path):
    g = _gate(tmp_path, enabled=True)

    async def _run():
        return "done"

    with pytest.raises(GateDenied):
        await g.execute_async(target="web-01", actor="james", token="", run=_run)


# ── gating_dir resolution ─────────────────────────────────────────────
def test_gating_dir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("F0_GATING_DIR", str(tmp_path / "g"))
    assert gating_dir() == tmp_path / "g"


def test_gating_dir_defaults_to_home(monkeypatch):
    monkeypatch.delenv("F0_GATING_DIR", raising=False)
    assert gating_dir().name == "gating"
    assert gating_dir().parent.name == ".f0sectools"


def test_gating_dir_expands_tilde(monkeypatch):
    monkeypatch.setenv("F0_GATING_DIR", "~/x-gating-test")
    assert gating_dir() == Path.home() / "x-gating-test"


def test_default_stores_anchor_on_gating_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("F0_GATING_DIR", str(tmp_path / "g"))
    assert TokenStore().dir == tmp_path / "g" / "tokens"
    assert AuditLog().path == tmp_path / "g" / "audit.log"
    assert ApprovalStore().requests == tmp_path / "g" / "requests"


def test_explicit_store_paths_expand_tilde():
    assert AuditLog("~/x-audit-test.log").path == Path.home() / "x-audit-test.log"
    assert TokenStore("~/x-tokens-test").dir == Path.home() / "x-tokens-test"
    assert ApprovalStore("~/x-gating-test").requests == Path.home() / "x-gating-test" / "requests"


# ── ApprovalStore lifecycle ───────────────────────────────────────────
def _approvals(tmp_path) -> ApprovalStore:
    return ApprovalStore(str(tmp_path / "gating"))


def test_approve_then_consume_succeeds_once(tmp_path):
    s = _approvals(tmp_path)
    s.approve("projectachilles.run_test", "uuid@host")
    assert s.consume("projectachilles.run_test", "uuid@host") is True
    assert s.consume("projectachilles.run_test", "uuid@host") is False  # single-use


def test_consume_rejected_for_wrong_target(tmp_path):
    s = _approvals(tmp_path)
    s.approve("projectachilles.run_test", "uuid@host-a")
    assert s.consume("projectachilles.run_test", "uuid@host-b") is False
    # the approval for host-a is still intact (different key, nothing burned)
    assert s.consume("projectachilles.run_test", "uuid@host-a") is True


def test_expired_approval_rejected_and_swept(tmp_path):
    s = _approvals(tmp_path)
    s.approve("a.b", "t", ttl_s=-1)
    assert s.has_approval("a.b", "t") is False
    assert s.consume("a.b", "t") is False
    assert list(s.approvals.glob("*.json")) == []  # swept


def test_has_approval_does_not_consume(tmp_path):
    s = _approvals(tmp_path)
    s.approve("a.b", "t")
    assert s.has_approval("a.b", "t") is True
    assert s.has_approval("a.b", "t") is True   # still there
    assert s.consume("a.b", "t") is True


def test_record_request_idempotent_and_listed(tmp_path):
    s = _approvals(tmp_path)
    s.record_request("a.b", "t")
    s.record_request("a.b", "t")  # refresh, not duplicate
    pending = s.list_pending()
    assert len(pending) == 1
    assert pending[0]["action"] == "a.b"
    assert pending[0]["target"] == "t"


def test_expired_request_not_listed(tmp_path):
    s = _approvals(tmp_path)
    s.record_request("a.b", "t", ttl_s=-1)
    assert s.list_pending() == []


def test_approve_clears_the_request(tmp_path):
    s = _approvals(tmp_path)
    s.record_request("a.b", "t")
    s.approve("a.b", "t")
    assert s.list_pending() == []
    assert s.has_approval("a.b", "t") is True


def test_deny_removes_request_without_approving(tmp_path):
    s = _approvals(tmp_path)
    s.record_request("a.b", "t")
    s.deny("a.b", "t")
    assert s.list_pending() == []
    assert s.has_approval("a.b", "t") is False


def test_approval_consume_lost_claim_returns_false(tmp_path):
    # Simulates a lost race: the approval file vanishes (e.g. a concurrent
    # claimant) between the is_file() check and the atomic unlink.
    s = _approvals(tmp_path)
    s.approve("a.b", "t")
    record_path = s.approvals / f"{ApprovalStore._key('a.b', 't')}.json"
    record_path.unlink()
    assert s.consume("a.b", "t") is False


def test_requests_are_not_authorization(tmp_path):
    s = _approvals(tmp_path)
    s.record_request("a.b", "t")
    assert s.has_approval("a.b", "t") is False
    assert s.consume("a.b", "t") is False


# ── GatedAction approval path ────────────────────────────────────────
def test_no_token_with_approval_executes_and_audits_method(tmp_path):
    g = _gate(tmp_path, enabled=True)
    g.approvals.approve("defender.isolate_host", "web-01")
    result = g.execute(target="web-01", actor="james", token=None, run=lambda: "ok")
    assert result == "ok"
    entry = json.loads((tmp_path / "a.log").read_text().strip())
    assert entry["method"] == "approval"
    assert entry["token_ref"]  # approval key prefix, non-empty
    # single-use: same call again is denied
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token=None, run=lambda: "ok")


def test_approval_cannot_bypass_disabled_flag(tmp_path):
    g = _gate(tmp_path, enabled=False)
    g.approvals.approve("defender.isolate_host", "web-01")
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token=None, run=lambda: "ok")
    # flag check is OUTERMOST: the approval must not have been consumed
    assert g.approvals.has_approval("defender.isolate_host", "web-01") is True


def test_approval_for_other_target_denied(tmp_path):
    g = _gate(tmp_path, enabled=True)
    g.approvals.approve("defender.isolate_host", "web-02")
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token=None, run=lambda: "ok")


def test_token_path_still_audits_method_token(tmp_path):
    g = _gate(tmp_path, enabled=True)
    tok = g.token_store.issue("defender.isolate_host", "web-01")
    g.execute(target="web-01", actor="james", token=tok, run=lambda: "ok")
    entry = json.loads((tmp_path / "a.log").read_text().strip())
    assert entry["method"] == "token"


def test_supplied_token_takes_precedence_and_bad_token_denies(tmp_path):
    # A bad token must deny even when an approval exists — no silent fallback
    # from an explicitly-supplied (wrong) credential.
    g = _gate(tmp_path, enabled=True)
    g.approvals.approve("defender.isolate_host", "web-01")
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token="nope", run=lambda: "ok")
    assert g.approvals.has_approval("defender.isolate_host", "web-01") is True


def test_gate_helpers_delegate(tmp_path):
    g = _gate(tmp_path, enabled=True)
    assert g.has_approval("web-01") is False
    g.record_request("web-01")
    assert g.approvals.list_pending()[0]["target"] == "web-01"
    g.approvals.approve("defender.isolate_host", "web-01")
    assert g.has_approval("web-01") is True
