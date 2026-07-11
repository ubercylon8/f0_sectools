import json

import pytest
from f0_sectools_core.gating.actions import (
    AuditLog,
    GatedAction,
    GateDenied,
    TokenStore,
)


def _gate(tmp_path, enabled):
    return GatedAction(
        "defender.isolate_host",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "a.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
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


def test_token_rejected_for_wrong_action(tmp_path):
    store = TokenStore(str(tmp_path / "pending"))
    tok = store.issue("defender.isolate_host", "web-01")
    assert store.consume("defender.release_host", "web-01", tok) is False


def test_expired_token_rejected(tmp_path):
    store = TokenStore(str(tmp_path / "pending"))
    tok = store.issue("defender.isolate_host", "web-01", ttl_s=-1)  # already expired
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
