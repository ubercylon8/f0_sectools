# Approval-Watcher Gating (Low-Friction Confirmation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator authorize a gated write with one keypress in a watcher terminal (`confirm_action.py --watch`) instead of copy-pasting a token through the chat — same flag/single-use/target-bound/TTL/audit guarantees, token flow kept as fallback.

**Architecture:** `core/gating` gains a fixed cross-process gating directory (`$F0_GATING_DIR` or `~/.f0sectools/gating/`) and an `ApprovalStore` (requests = display-only; approvals = human-CLI-written, single-use). `GatedAction._authorize` tries the token first, then a stored approval. Gated tools change one line each: intent is returned only when there is neither a token nor an approval, and the intent records a pending request for the watcher. The model's retry is the *identical* call — no schema change anywhere.

**Tech Stack:** Python 3.11+, stdlib only for the new core code (hashlib/json/time/pathlib/os), pytest for tests, argparse for the CLI.

**Spec:** `docs/superpowers/specs/2026-07-18-gating-approvals-design.md` (committed 2a83fd3). Branch: `feat/gating-approvals` (already checked out).

## Global Constraints

- **Invariants (spec, verbatim):** flag required; human-in-the-loop per action; single-use; target-bound; TTL'd (900 s default); locally audited; all gating logic in `core/gating`; approvals are host filesystem records that only the human-side CLI creates — **no MCP tool writes to the approvals directory** (`record_request` writes only to `requests/`, which is display data, never authorization).
- **Flag stays the outermost gate:** `_authorize` checks `enabled` before token AND before approval — an approval must never bypass a disabled platform.
- **Backward compat:** the legacy token flow works unchanged; all existing gate tests must stay green without behavioral edits (fixtures may gain an `approvals=` arg for hermeticity, assertions unchanged).
- **Tool signatures and MCP schemas are untouched** — zero eval/callability impact.
- **Hermetic tests:** every test that constructs a `GatedAction` MUST pass `approvals=ApprovalStore(str(tmp_path / "gating"))` so no test ever reads or writes the real `~/.f0sectools`.
- **Existing intent-text assertions keep passing:** pa-actions tests assert the target string and `--platform projectachilles` appear in the intent summary; defender/pa new intent text must retain those substrings.
- **Gating dir resolution:** `$F0_GATING_DIR` if set, else `~/.f0sectools/gating/`; layout `requests/`, `approvals/`, `tokens/` (new TokenStore default), `audit.log` (new AuditLog default). Existing `*_AUDIT_LOG_PATH` env overrides keep working (they pass an explicit path).
- Record key = `sha256("{action}|{target}")`; single-use consume uses unlink-before-validate (same discipline as `TokenStore.consume`).
- Audit entries gain `method`: `"token" | "approval" | "denied"`.
- NO `tests/__init__.py` anywhere new; verification per task = named pytest scope + `uv run ruff check .` + `uv run mypy .` (root gates); commits conventional, no backticks in `-m`, stage specific files, never push.

---

### Task 1: `gating_dir()` + `ApprovalStore` + store default-dir move (core)

**Files:**
- Modify: `core/f0_sectools_core/gating/actions.py` (add `os` import, `gating_dir()`, `ApprovalStore`; change `TokenStore.__init__` and `AuditLog.__init__` defaults)
- Test: `core/tests/test_gating.py` (append)

**Interfaces:**
- Produces (Tasks 2–5 depend on these exact names):
  - `gating_dir() -> Path`
  - `class ApprovalStore` with `__init__(dir: str | None = None)`, attributes `requests: Path` / `approvals: Path`, static `_key(action, target) -> str`, methods `record_request(action, target, ttl_s=900)`, `list_pending() -> list[dict[str, Any]]`, `approve(action, target, ttl_s=900)`, `deny(action, target)`, `has_approval(action, target) -> bool`, `consume(action, target) -> bool`.
  - `TokenStore()` default dir becomes `gating_dir() / "tokens"`; `AuditLog()` default path becomes `gating_dir() / "audit.log"`. Explicit-arg behavior unchanged.

- [ ] **Step 1: Write the failing tests** — append to `core/tests/test_gating.py`:

```python
from f0_sectools_core.gating.actions import ApprovalStore, gating_dir


# ── gating_dir resolution ─────────────────────────────────────────────
def test_gating_dir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("F0_GATING_DIR", str(tmp_path / "g"))
    assert gating_dir() == tmp_path / "g"


def test_gating_dir_defaults_to_home(monkeypatch):
    monkeypatch.delenv("F0_GATING_DIR", raising=False)
    assert gating_dir().name == "gating"
    assert gating_dir().parent.name == ".f0sectools"


def test_default_stores_anchor_on_gating_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("F0_GATING_DIR", str(tmp_path / "g"))
    assert TokenStore().dir == tmp_path / "g" / "tokens"
    assert AuditLog().path == tmp_path / "g" / "audit.log"
    assert ApprovalStore().requests == tmp_path / "g" / "requests"


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


def test_requests_are_not_authorization(tmp_path):
    s = _approvals(tmp_path)
    s.record_request("a.b", "t")
    assert s.has_approval("a.b", "t") is False
    assert s.consume("a.b", "t") is False
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest core/tests/test_gating.py -v -k "gating_dir or approval or request or deny"`
Expected: FAIL — `ImportError: cannot import name 'ApprovalStore'`

- [ ] **Step 3: Implement in `core/f0_sectools_core/gating/actions.py`**

Add `import os` to the imports. After the module docstring/imports, add:

```python
def gating_dir() -> Path:
    """Fixed cross-process gating-state root — servers and the operator CLI
    must agree on it regardless of their working directories."""
    env = os.environ.get("F0_GATING_DIR")
    return Path(env) if env else Path.home() / ".f0sectools" / "gating"
```

Change the two defaults (explicit args keep working):

```python
class AuditLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else gating_dir() / "audit.log"
```

```python
class TokenStore:
    def __init__(self, dir: str | None = None) -> None:
        self.dir = Path(dir) if dir else gating_dir() / "tokens"
```

Add the new class (between `TokenStore` and `GatedAction`):

```python
class ApprovalStore:
    """Pending requests + human-granted pre-approvals, keyed by (action, target).

    Requests (written by servers when they return an intent) are display data
    for the operator watcher — NEVER authorization. Approvals are written only
    by the human-side CLI (scripts/confirm_action.py); consuming one is
    single-use with the same unlink-before-validate discipline as TokenStore,
    so concurrent callers cannot both win.
    """

    def __init__(self, dir: str | None = None) -> None:
        root = Path(dir) if dir else gating_dir()
        self.requests = root / "requests"
        self.approvals = root / "approvals"

    @staticmethod
    def _key(action: str, target: str) -> str:
        return hashlib.sha256(f"{action}|{target}".encode("utf-8")).hexdigest()

    @staticmethod
    def _sweep(dir_: Path) -> None:
        if not dir_.is_dir():
            return
        now = time.time()
        for f in dir_.glob("*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if float(rec.get("expires_at", 0)) < now:
                f.unlink(missing_ok=True)

    def record_request(self, action: str, target: str, ttl_s: int = 900) -> None:
        self.requests.mkdir(parents=True, exist_ok=True)
        self._sweep(self.requests)
        record = {
            "action": action,
            "target": target,
            "requested_at": time.time(),
            "expires_at": time.time() + ttl_s,
        }
        (self.requests / f"{self._key(action, target)}.json").write_text(
            json.dumps(record), encoding="utf-8"
        )

    def list_pending(self) -> list[dict[str, Any]]:
        self._sweep(self.requests)
        out: list[dict[str, Any]] = []
        if self.requests.is_dir():
            for f in sorted(self.requests.glob("*.json")):
                try:
                    out.append(json.loads(f.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    continue
        return out

    def approve(self, action: str, target: str, ttl_s: int = 900) -> None:
        self.approvals.mkdir(parents=True, exist_ok=True)
        self._sweep(self.approvals)
        record = {"action": action, "target": target, "expires_at": time.time() + ttl_s}
        (self.approvals / f"{self._key(action, target)}.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        (self.requests / f"{self._key(action, target)}.json").unlink(missing_ok=True)

    def deny(self, action: str, target: str) -> None:
        (self.requests / f"{self._key(action, target)}.json").unlink(missing_ok=True)

    def has_approval(self, action: str, target: str) -> bool:
        self._sweep(self.approvals)
        return (self.approvals / f"{self._key(action, target)}.json").is_file()

    def consume(self, action: str, target: str) -> bool:
        self._sweep(self.approvals)
        path = self.approvals / f"{self._key(action, target)}.json"
        if not path.is_file():
            return False
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        path.unlink(missing_ok=True)  # single-use: gone whether or not it validates
        if record.get("action") != action or record.get("target") != target:
            return False
        if float(record.get("expires_at", 0)) < time.time():
            return False
        return True
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest core/tests/test_gating.py -v && uv run ruff check core && uv run mypy .`
Expected: all PASS (existing token tests included), clean

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/gating/actions.py core/tests/test_gating.py
git commit -m "feat(gating): ApprovalStore and fixed gating dir for cross-process stores"
```

---

### Task 2: `GatedAction` approval path + audit `method`

**Files:**
- Modify: `core/f0_sectools_core/gating/actions.py` (`AuditLog.record`, `GatedAction`)
- Test: `core/tests/test_gating.py` (append; also update its `_gate` helper)

**Interfaces:**
- Consumes: Task 1's `ApprovalStore`.
- Produces (Tasks 3–4 depend on these exact names):
  - `GatedAction.__init__(name, enabled, audit, token_store, approvals: ApprovalStore | None = None)` — `None` → `ApprovalStore()` on the default gating dir.
  - `GatedAction.has_approval(target: str) -> bool` (non-consuming peek).
  - `GatedAction.record_request(target: str) -> None`.
  - `_authorize(target, token) -> str` returns the method (`"token"` / `"approval"`), raises `GateDenied` otherwise; `execute`/`execute_async` behavior unchanged for callers.
  - `AuditLog.record(action, target, actor, token, method: str = "token", ref: str | None = None)` — entry gains `"method"`; `token_ref` uses `ref` when given, else the token hash prefix as today.

- [ ] **Step 1: Write the failing tests** — in `core/tests/test_gating.py`, first update the module's `_gate` helper (hermeticity — required by Global Constraints):

```python
def _gate(tmp_path, enabled):
    return GatedAction(
        "defender.isolate_host",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "a.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
        approvals=ApprovalStore(str(tmp_path / "gating")),
    )
```

Then append:

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest core/tests/test_gating.py -v -k "approval or method or delegate"`
Expected: FAIL — `TypeError: ... unexpected keyword argument 'approvals'`

- [ ] **Step 3: Implement**

`AuditLog.record` becomes:

```python
    def record(
        self,
        action: str,
        target: str,
        actor: str,
        token: str,
        method: str = "token",
        ref: str | None = None,
    ) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if ref is not None:
            token_ref = ref
        else:
            token_ref = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else ""
        entry = {
            "action": action,
            "target": target,
            "actor": actor,
            "method": method,
            "token_ref": token_ref,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
```

`GatedAction` becomes:

```python
class GatedAction:
    def __init__(
        self,
        name: str,
        enabled: bool,
        audit: AuditLog,
        token_store: TokenStore,
        approvals: ApprovalStore | None = None,
    ) -> None:
        self.name = name
        self.enabled = enabled
        self.audit = audit
        self.token_store = token_store
        self.approvals = approvals if approvals is not None else ApprovalStore()

    def has_approval(self, target: str) -> bool:
        """Non-consuming peek — lets a tool decide intent vs execute."""
        return self.approvals.has_approval(self.name, target)

    def record_request(self, target: str) -> None:
        """Publish a pending request for the operator watcher (display only)."""
        self.approvals.record_request(self.name, target)

    def _authorize(self, target: str, token: str | None) -> str:
        if not self.enabled:
            raise GateDenied(
                f"Action '{self.name}' is disabled. Set the platform write flag to enable it."
            )
        if token:
            if self.token_store.consume(self.name, target, token):
                return "token"
            raise GateDenied(
                f"Action '{self.name}' requires a fresh, valid confirmation token."
            )
        if self.approvals.consume(self.name, target):
            return "approval"
        raise GateDenied(
            f"Action '{self.name}' requires a watcher approval "
            f"(confirm_action.py --watch) or a confirmation token."
        )

    def _audit(self, target: str, actor: str, token: str | None, method: str) -> None:
        ref = (
            ApprovalStore._key(self.name, target)[:16] if method == "approval" else None
        )
        self.audit.record(self.name, target, actor, token or "", method=method, ref=ref)

    def execute(
        self, *, target: str, actor: str, token: str | None, run: Callable[[], Any]
    ) -> Any:
        method = self._authorize(target, token)
        result = run()
        self._audit(target, actor, token, method)
        return result

    async def execute_async(
        self,
        *,
        target: str,
        actor: str,
        token: str | None,
        run: Callable[[], Awaitable[Any]],
    ) -> Any:
        method = self._authorize(target, token)
        result = await run()
        self._audit(target, actor, token, method)
        return result
```

- [ ] **Step 4: Run the full core suite, lint, type-check**

Run: `uv run pytest core -v && uv run ruff check core && uv run mypy .`
Expected: all PASS (every pre-existing token test green, unchanged assertions), clean

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/gating/actions.py core/tests/test_gating.py
git commit -m "feat(gating): approval path in GatedAction with audited method"
```

---

### Task 3: Defender — intent-or-approval short-circuit + hermetic fixtures

**Files:**
- Modify: `servers/defender-mcp/f0_defender_mcp/tools.py` (`_run_machine_action` short-circuit at ~line 356; `_intent_finding` summary at ~line 322)
- Test: `servers/defender-mcp/tests/test_tools.py` (update `_gate` fixture; append tests)

**Interfaces:**
- Consumes: Task 2's `GatedAction.has_approval(target)` / `record_request(target)`, Task 1's `ApprovalStore`.
- Produces: nothing new for later tasks — Task 4 mirrors this pattern in the other server.

- [ ] **Step 1: Update the test fixture (hermeticity) and write the failing tests**

In `servers/defender-mcp/tests/test_tools.py`, add `ApprovalStore` to the existing `f0_sectools_core.gating.actions` import and update `_gate`:

```python
def _gate(tmp_path, enabled):
    return GatedAction(
        "defender.isolate_host",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "a.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
        approvals=ApprovalStore(str(tmp_path / "gating")),
    )
```

Append:

```python
@pytest.mark.asyncio
async def test_isolate_host_intent_records_pending_request(tmp_path):
    with respx.mock as router:
        _token(router)
        router.post(SEC + "/machines/dev-1/isolate")
        gate = _gate(tmp_path, enabled=True)
        async with _sec_client() as sec:
            await isolate_host(sec, gate, "dev-1", "suspected c2")
    pending = gate.approvals.list_pending()
    assert len(pending) == 1
    assert pending[0]["action"] == "defender.isolate_host"
    assert pending[0]["target"] == "dev-1"


@pytest.mark.asyncio
async def test_isolate_host_same_call_after_approval_executes(tmp_path):
    with respx.mock as router:
        _token(router)
        post = router.post(SEC + "/machines/dev-1/isolate").mock(
            return_value=httpx.Response(201, json={"id": "act-1", "status": "Pending"})
        )
        gate = _gate(tmp_path, enabled=True)
        gate.approvals.approve("defender.isolate_host", "dev-1")
        async with _sec_client() as sec:
            findings = await isolate_host(sec, gate, "dev-1", "suspected c2")
    assert post.call_count == 1
    assert "Action completed" in findings[0].title
    import json as _json
    entry = _json.loads((tmp_path / "a.log").read_text().strip())
    assert entry["method"] == "approval"


@pytest.mark.asyncio
async def test_isolate_host_approval_for_other_device_still_intent(tmp_path):
    with respx.mock as router:
        _token(router)
        post = router.post(SEC + "/machines/dev-1/isolate")
        gate = _gate(tmp_path, enabled=True)
        gate.approvals.approve("defender.isolate_host", "dev-9")
        async with _sec_client() as sec:
            findings = await isolate_host(sec, gate, "dev-1", "c2")
    assert not post.called
    assert "Pending action" in findings[0].title
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/defender-mcp/tests/test_tools.py -v -k "pending_request or after_approval or other_device"`
Expected: FAIL — `test_isolate_host_intent_records_pending_request` fails (no request recorded); `after_approval` returns intent instead of executing.

- [ ] **Step 3: Implement in `servers/defender-mcp/f0_defender_mcp/tools.py`**

Change the short-circuit in `_run_machine_action` from:

```python
    if not confirmation_token:
        return [_intent_finding(gate.name, verb, device_id, comment, intent_extra)]
```

to:

```python
    if not confirmation_token and not gate.has_approval(device_id):
        gate.record_request(device_id)
        return [_intent_finding(gate.name, verb, device_id, comment, intent_extra)]
```

Change `_intent_finding`'s `recommended_action` summary from:

```python
            summary=(
                f"To execute, an operator must run: python scripts/confirm_action.py "
                f"{action_name.split('.')[-1]} {device_id} — then call this tool again "
                f"with the printed confirmation_token."
            ),
```

to:

```python
            summary=(
                "To execute: an operator approves this action in their "
                "confirm_action.py --watch terminal, then you call this tool again "
                "with the SAME arguments.\n"
                "Token fallback: python scripts/confirm_action.py "
                f"{action_name.split('.')[-1]} {device_id}\n"
                "then pass the printed confirmation_token."
            ),
```

- [ ] **Step 4: Run the defender suite, lint, type-check**

Run: `uv run pytest servers/defender-mcp -v && uv run ruff check servers/defender-mcp && uv run mypy .`
Expected: all PASS (existing intent/refusal tests unchanged and green), clean

- [ ] **Step 5: Commit**

```bash
git add servers/defender-mcp/f0_defender_mcp/tools.py servers/defender-mcp/tests/test_tools.py
git commit -m "feat(defender): gated writes accept watcher approvals on the identical retry"
```

---

### Task 4: pa-actions — the same short-circuit at all 4 gated sites

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (4 short-circuits at ~lines 127, 289, 374, 430; `_intent` summary at ~line 48)
- Test: update `_gate` fixtures in `servers/projectachilles-actions-mcp/tests/test_run_test.py`, `tests/test_schedule_test.py`, `tests/test_schedule_status_and_cancel.py`; append approval tests to `test_run_test.py` and `test_schedule_status_and_cancel.py`

**Interfaces:**
- Consumes: Task 2's `has_approval` / `record_request`; Task 1's `ApprovalStore`.

- [ ] **Step 1: Update fixtures (hermeticity) and write the failing tests**

In each of the three test files, add `ApprovalStore` to the `f0_sectools_core.gating.actions` import and add the `approvals=` line to the existing `_gate` helper, e.g. in `test_run_test.py`:

```python
def _gate(tmp_path, enabled: bool = True) -> GatedAction:
    return GatedAction(
        "projectachilles.run_test",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "audit.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
        approvals=ApprovalStore(str(tmp_path / "gating")),
    )
```

(`test_schedule_test.py` and `test_schedule_status_and_cancel.py` have the same helper shape — `test_schedule_status_and_cancel.py`'s takes the gate `name` as a parameter; add the same `approvals=` line.)

Append to `test_run_test.py`:

```python
@pytest.mark.asyncio
async def test_run_test_intent_records_pending_request(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        router.post(f"{BASE}/api/agent/admin/tasks")
        gate = _gate(tmp_path)
        async with ProjectAchillesClient(_cfg()) as pa:
            await run_test(pa, gate, UUID, "web-01")
    pending = gate.approvals.list_pending()
    assert len(pending) == 1
    assert pending[0]["target"] == TARGET


@pytest.mark.asyncio
async def test_run_test_same_call_after_approval_executes(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(201, json={"data": {"task_ids": ["task-1"]}})
        )
        gate = _gate(tmp_path)
        gate.approvals.approve("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, gate, UUID, "web-01")
    assert post.call_count == 1
    assert "Action completed" in findings[0].title
    entry = json.loads((tmp_path / "audit.log").read_text().strip())
    assert entry["method"] == "approval"


@pytest.mark.asyncio
async def test_run_test_approval_for_other_host_still_intent(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        gate = _gate(tmp_path)
        gate.approvals.approve("projectachilles.run_test", f"{UUID}@db-01")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, gate, UUID, "web-01")
    assert post.called is False
    assert "Pending action" in findings[0].title
```

Append to `test_schedule_status_and_cancel.py`:

```python
@pytest.mark.asyncio
async def test_pause_same_call_after_approval_executes(tmp_path):
    with respx.mock() as router:
        patch = router.patch(f"{BASE}/api/agent/admin/schedules/sched-1").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "sched-1", "status": "paused", "next_run_at": None,
            }})
        )
        gate = _gate(tmp_path, "projectachilles.set_schedule_status")
        gate.approvals.approve("projectachilles.set_schedule_status", "sched-1:paused")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await set_schedule_status(pa, gate, "sched-1", "paused")
    assert patch.call_count == 1
    assert "Action completed" in findings[0].title


@pytest.mark.asyncio
async def test_cancel_intent_records_pending_request(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE}/api/agent/admin/tasks/task-1/cancel")
        gate = _gate(tmp_path, "projectachilles.cancel_task")
        async with ProjectAchillesClient(_cfg()) as pa:
            await cancel_task(pa, gate, "task-1")
    assert gate.approvals.list_pending()[0]["target"] == "task-1"
```

(`test_run_test.py` needs `import json` at top if not present.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests -v -k "pending_request or after_approval or other_host"`
Expected: FAIL — intents don't record requests; approved retries still return intent.

- [ ] **Step 3: Implement in `f0_pa_actions_mcp/tools.py`**

At each of the 4 gated sites, change the short-circuit and add the request line. The condition/first-line pattern is identical; the four `target` variables are the existing ones:

`run_test` (~line 127):
```python
    if not confirmation_token and not gate.has_approval(target):
        gate.record_request(target)
        return [
```
`schedule_test` (~line 289): same two-line change (its short-circuit also returns a `[ _intent(...) ]` block).
`set_schedule_status` (~line 374):
```python
    if not confirmation_token and not gate.has_approval(target):
        gate.record_request(target)
        return [_intent(gate.name, target, f"{verb} schedule {sid}", entity, evidence)]
```
`cancel_task` (~line 430):
```python
    if not confirmation_token and not gate.has_approval(target):
        gate.record_request(target)
        return [_intent(gate.name, target, f"cancel task {tid}", entity, evidence)]
```

Change `_intent`'s summary (keeps the target string and `--platform projectachilles` substrings that existing tests assert):

```python
            summary=(
                "To execute: an operator approves this action in their "
                "confirm_action.py --watch terminal, then you call this tool again "
                "with the SAME arguments.\n"
                "Token fallback: python scripts/confirm_action.py "
                f'{short} "{target}" --platform projectachilles\n'
                "then pass the printed confirmation_token."
            ),
```

- [ ] **Step 4: Run the pa-actions suite, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy .`
Expected: all PASS — including every pre-existing negative-space and intent-text assertion — clean

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py servers/projectachilles-actions-mcp/tests
git commit -m "feat(pa-actions): gated writes accept watcher approvals on the identical retry"
```

---

### Task 5: `confirm_action.py` — watch / approve / list / deny

**Files:**
- Modify: `scripts/confirm_action.py` (rewrite; legacy token mode preserved verbatim in behavior)
- Test: `scripts/test_confirm_action.py` (new; no `__init__.py`)

**Interfaces:**
- Consumes: Task 1's `ApprovalStore` (+ `AuditLog` for denial records).
- Produces: operator CLI. Testable functions: `issue_confirmation(...)` (unchanged), `resolve_action(action, platform) -> str`, `approve_one(store, audit, action, target, ttl_s) -> None`, `deny_one(store, audit, action, target) -> None`, `watch_once(store, audit, ask, notify=None) -> int` (returns number of items handled; `ask` is a callable returning "y"/"n" so tests never fake a TTY).

- [ ] **Step 1: Write the failing tests** — `scripts/test_confirm_action.py`:

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest scripts/test_confirm_action.py -v`
Expected: FAIL — `ImportError: cannot import name 'approve_one'`

- [ ] **Step 3: Rewrite `scripts/confirm_action.py`**

```python
"""Out-of-band confirmation for gated write actions — token issuer + approval watcher.

Two ways to authorize one gated action (both single-use, target-bound, TTL'd,
audited; the model can invoke neither):

  WATCHER (lowest friction — keep this running in a spare terminal/tmux pane):
      python scripts/confirm_action.py --watch [--notify]
  Pending gated calls appear as they happen; answer y/N. Then tell the agent
  "approved" — it repeats the identical tool call and the gate consumes the
  approval. No token is ever pasted anywhere.

  ONE-SHOT:
      python scripts/confirm_action.py --approve run_test "<target>" --platform projectachilles
      python scripts/confirm_action.py --list

  LEGACY TOKEN (kept for headless/scripted flows, e.g. live-smoke --execute):
      python scripts/confirm_action.py isolate_host <device_id> [--ttl 900]
  Paste the printed token into the tool's `confirmation_token` argument.

State lives under $F0_GATING_DIR (default ~/.f0sectools/gating), shared with
the MCP servers regardless of working directory.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import time
from collections.abc import Callable

from f0_sectools_core.gating.actions import ApprovalStore, AuditLog, TokenStore

_ACTOR = "operator-cli"


def resolve_action(action: str, platform: str) -> str:
    return action if "." in action else f"{platform}.{action}"


def issue_confirmation(
    action: str,
    target: str,
    ttl_s: int = 900,
    store: TokenStore | None = None,
    platform: str = "defender",
) -> str:
    store = store or TokenStore()
    return store.issue(resolve_action(action, platform), target, ttl_s)


def approve_one(
    store: ApprovalStore, audit: AuditLog, action: str, target: str, ttl_s: int = 900
) -> None:
    store.approve(action, target, ttl_s=ttl_s)
    audit.record(action, target, _ACTOR, "", method="approved")


def deny_one(store: ApprovalStore, audit: AuditLog, action: str, target: str) -> None:
    store.deny(action, target)
    audit.record(action, target, _ACTOR, "", method="denied")


def _desktop_notify(message: str) -> None:
    exe = shutil.which("notify-send")
    if exe:
        subprocess.run(  # noqa: S603 — fixed local binary, no shell, operator's own session
            [exe, "f0_sectools gated action", message], check=False
        )


def watch_once(
    store: ApprovalStore,
    audit: AuditLog,
    ask: Callable[[str], str],
    notify: Callable[[str], None] | None = None,
) -> int:
    """Handle every currently-pending request; returns how many were handled."""
    handled = 0
    for req in store.list_pending():
        action, target = str(req.get("action")), str(req.get("target"))
        if notify:
            notify(f"{action} -> {target}")
        answer = ask(f"{action} -> {target} — approve? [y/N] ").strip().lower()
        if answer == "y":
            approve_one(store, audit, action, target)
            print(f"APPROVED {action} -> {target} (15 min, single use)")
        else:
            deny_one(store, audit, action, target)
            print(f"denied {action} -> {target}")
        handled += 1
    return handled


def _watch_loop(store: ApprovalStore, audit: AuditLog, interval: float, notify: bool) -> int:
    print(f"Watching for gated-action requests ({store.requests}) — Ctrl-C to stop.")
    notifier = _desktop_notify if notify else None
    try:
        while True:
            watch_once(store, audit, ask=input, notify=notifier)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nwatcher stopped.")
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Authorize gated write actions (watcher approvals or one-shot tokens)."
    )
    parser.add_argument("action", nargs="?", help="e.g. isolate_host, run_test")
    parser.add_argument("target", nargs="?", help="the exact target the action will affect")
    parser.add_argument("--platform", default="defender")
    parser.add_argument("--ttl", type=int, default=900, help="seconds until expiry")
    parser.add_argument("--store-dir", default=None, help="override the gating state dir")
    parser.add_argument("--watch", action="store_true", help="interactive approval watcher")
    parser.add_argument("--notify", action="store_true", help="notify-send on pending items")
    parser.add_argument("--interval", type=float, default=2.0, help="watch poll seconds")
    parser.add_argument("--approve", action="store_true",
                        help="approve ACTION TARGET without a token")
    parser.add_argument("--list", action="store_true", dest="list_pending",
                        help="list pending requests")
    args = parser.parse_args(argv)

    approvals = ApprovalStore(args.store_dir)
    audit = AuditLog(str(args.store_dir) + "/audit.log") if args.store_dir else AuditLog()

    if args.watch:
        return _watch_loop(approvals, audit, args.interval, args.notify)

    if args.list_pending:
        pending = approvals.list_pending()
        if not pending:
            print("no pending gated-action requests.")
        for req in pending:
            print(f"{req.get('action')} -> {req.get('target')}")
        return 0

    if args.approve:
        if not (args.action and args.target):
            parser.error("--approve needs ACTION and TARGET")
        action = resolve_action(args.action, args.platform)
        approve_one(approvals, audit, action, args.target, ttl_s=args.ttl)
        print(f"APPROVED {action} -> {args.target} "
              f"(valid {args.ttl}s, single use) — tell the agent to retry the same call.")
        return 0

    # Legacy token mode
    if not (args.action and args.target):
        parser.error("provide ACTION and TARGET (or use --watch / --list / --approve)")
    store = TokenStore(args.store_dir) if args.store_dir else None
    token = issue_confirmation(
        args.action, args.target, ttl_s=args.ttl, store=store, platform=args.platform
    )
    print(f"Confirmation token for {resolve_action(args.action, args.platform)} "
          f"on {args.target}:")
    print(token)
    print(f"(valid {args.ttl}s, single use) — paste into the tool's "
          "confirmation_token argument.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run tests, lint**

Run: `uv run pytest scripts -v && uv run ruff check scripts && uv run mypy .`
Expected: all PASS (scripts are mypy-excluded; the run confirms no repo-wide regression), clean

- [ ] **Step 5: Commit**

```bash
git add scripts/confirm_action.py scripts/test_confirm_action.py
git commit -m "feat(scripts): confirm_action watcher with approve/deny/list modes"
```

---

### Task 6: Docs + skill

**Files:**
- Modify: `CLAUDE.md` (Gated Write Actions section)
- Modify: `skills/projectachilles/run-validation-test/SKILL.md` (Procedure step 3; Pitfalls)
- Modify: `servers/projectachilles-actions-mcp/README.md`, `servers/defender-mcp/README.md` (confirmation-flow passages)
- Modify: `servers/projectachilles-mcp/.env.projectachilles.example`, `servers/defender-mcp/.env.defender.example` (mention `F0_GATING_DIR` + watcher)
- Modify: `docs/user-guide/README.md` (gated-writes passage, if present — read first)

- [ ] **Step 1: CLAUDE.md** — in "Gated Write Actions", replace step 3 ("Confirmation token required...") with a two-mode description (keep steps 1, 2, 4 intact):

```markdown
3. **Human confirmation required.** Two equivalent modes, both single-use,
   target-bound, TTL'd, and implemented in `core/gating/`:
   - **Watcher (default):** the intent registers a pending request; the
     operator approves it in `python scripts/confirm_action.py --watch`
     (one keypress), and the agent repeats the *identical* tool call — the
     gate consumes the stored approval. No token ever enters model context.
   - **Token (headless/scripted):** `confirm_action.py <action> "<target>"`
     prints a single-use token passed as `confirmation_token` (used by e.g.
     the live-smoke `--execute` flows).
   Gating state lives under `$F0_GATING_DIR` (default `~/.f0sectools/gating/`),
   shared by servers and the CLI regardless of working directory. No
   confirmation → no execution.
```

- [ ] **Step 2: Skill** — in `skills/projectachilles/run-validation-test/SKILL.md`, replace Procedure steps 3–4 (the "STOP and hand the operator the exact command" / "call again with the token" pair) with:

```markdown
3. STOP and ask the operator to approve the action in their
   `confirm_action.py --watch` terminal (the pending request appears there
   automatically; the intent finding shows the exact target). If they prefer
   tokens, the finding also carries the one-shot command.
4. Once the operator says approved, call the SAME tool again with the SAME
   arguments (no token needed — the gate consumes the stored approval).
   Approvals are single-use, expire in 15 minutes, and are bound to the
   exact action + target shown in the intent.
```

Keep the existing binding caveat sentence about schedule timing arguments.

- [ ] **Step 3: READMEs + .env examples** — read each file first, keep its format:
- pa-actions README "Setup" numbered list: describe the watcher as the primary flow (approve → retry same call), token as fallback; mention `F0_GATING_DIR`.
- defender README: same adjustment wherever `confirm_action.py` is described.
- Both `.env.*.example` files: extend the gating comment block with two lines — watcher usage and `# F0_GATING_DIR=~/.f0sectools/gating  (shared gating-state dir override)`.
- `docs/user-guide/README.md`: update any token-paste description to the watcher flow (read first; skip if it defers to the server READMEs).

- [ ] **Step 4: Full verification**

Run: `uv run pytest && uv run ruff check . && uv run mypy .`
Expected: ALL PASS, clean. Also `git status --short` shows no real `.env*` staged.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md skills/projectachilles/run-validation-test/SKILL.md servers/projectachilles-actions-mcp/README.md servers/defender-mcp/README.md servers/projectachilles-mcp/.env.projectachilles.example servers/defender-mcp/.env.defender.example docs/user-guide/README.md
git commit -m "docs(gating): document the approval-watcher confirmation flow"
```

---

## Plan Self-Review (done at write time)

- **Spec coverage:** gating dir + env override (T1); ApprovalStore semantics incl. requests-never-authorize (T1); GatedAction order flag→token→approval, helpers, audit method (T2); server short-circuits + intent text, defender 1 site (T3) + pa-actions 4 sites (T4); CLI watch/approve/list/deny + legacy kept (T5); docs/skill (T6). Spec milestone 5 (live pi check) is user-gated — intentionally not a task. Elicitation explicitly out of scope.
- **Type consistency:** `ApprovalStore(str(tmp_path / "gating"))` everywhere; `approve(action, target, ttl_s=900)`; `watch_once(store, audit, ask, notify=None)` matches T5 tests; audit `method` values `"token"|"approval"` (gate) and `"approved"|"denied"` (CLI grant/deny records — distinct on purpose: CLI records the *human decision*, the gate records the *execution*).
- **Known judgment points for implementers:** exact current line numbers may drift a few lines — anchor on the quoted code, not the numbers; `test_schedule_status_and_cancel.py`'s `_gate` takes `name` as a parameter (noted in T4).
