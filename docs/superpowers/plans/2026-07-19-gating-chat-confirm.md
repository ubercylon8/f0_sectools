# Chat-Confirm Gating Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in per-platform `confirm_mode="chat"` so a supervised operator can authorize a ProjectAchilles gated write by typing "approved" in the chat (the model re-calls the tool echoing the target), with the forge-resistant token/watcher path unchanged and default.

**Architecture:** One additive branch in `core/gating.GatedAction._authorize` (chat-mode target-echo → execute, audit `method="chat-confirm"`), a validated `confirm_mode` field on `ProjectAchillesConfig`, thin pa-actions wiring (`_gate` passes the mode, `_intent` text becomes mode-aware), and a Critical Rule 1 amendment. No tool signature / MCP schema change; Defender and every other platform untouched.

**Tech Stack:** Python 3.11+, stdlib only, pytest.

**Spec:** `docs/superpowers/specs/2026-07-19-gating-chat-confirm-design.md` (committed 371ba02). Branch: `feat/gating-chat-confirm` (checked out, rebased on main incl. the org_id fix).

## Global Constraints

- **Flag stays outermost:** `_authorize` checks `enabled` before any mode branch — a disabled platform denies even with a correct echo, and the echo is not consumed.
- **Chat-confirm is strictly additive:** in chat mode the token and watcher paths still work; the new branch only ADDS a third accepted route. In `token` mode nothing changes at all.
- **Echo rule:** chat-confirm accepts iff `confirm_mode == "chat"` AND `token == target` (exact string). A target-echo in `token` mode must fall through and DENY (no cross-mode leak).
- **Audit:** chat-confirm execution records `method="chat-confirm"` (add to the `_audit` ref rule so it carries the action|target key prefix, like `approval`).
- **No tool signature / MCP schema change** — the existing `confirmation_token` arg carries the echoed target.
- **PA-only wiring:** only `ProjectAchillesConfig` + pa-actions change. `PlatformConfig` (Defender/Entra/Intune) and the Defender server are NOT touched.
- **Config validation:** `PROJECTACHILLES_CONFIRM_MODE` default `"token"`, accepted values `{"token","chat"}`; any other value raises `ValueError` in `from_env` (never silently weaken the gate).
- **Governance:** CLAUDE.md Critical Rule 1 is amended in the same change to name the two confirmation modes (forge-resistant token/watcher = default + only option for destructive actions; chat-confirm = opt-in, reversible actions only, model-forgeable).
- **Hermetic tests:** every `GatedAction` in tests passes explicit tmp-dir stores; the core `_gate` helper gains a `confirm_mode` parameter (default `"token"`) so existing calls are unchanged.
- Existing token/approval tests stay green with unchanged assertions; existing pa-actions intent-text assertions (`target` string + `--platform projectachilles` in token-mode summary) stay green. Verification per task: named pytest scope + `uv run ruff check .` + `uv run mypy .`. Commits conventional, no backticks in `-m`, specific files staged, never push.

---

### Task 1: `confirm_mode` on `GatedAction` + `_authorize` chat branch

**Files:**
- Modify: `core/f0_sectools_core/gating/actions.py` (`GatedAction.__init__`, `_authorize`, `_audit`)
- Test: `core/tests/test_gating.py` (update the `_gate` helper; append tests)

**Interfaces:**
- Consumes: existing `ApprovalStore`, `TokenStore`, `AuditLog`.
- Produces: `GatedAction.__init__(name, enabled, audit, token_store, approvals=None, confirm_mode="token")`; `_authorize` returns `"chat-confirm"` on a chat echo; `_audit` carries the key-prefix ref for `chat-confirm` too.

- [ ] **Step 1: Update the `_gate` helper and write failing tests**

In `core/tests/test_gating.py`, update the module `_gate` helper to accept the mode (keeps every existing call working):

```python
def _gate(tmp_path, enabled, confirm_mode="token"):
    return GatedAction(
        "defender.isolate_host",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "a.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
        approvals=ApprovalStore(str(tmp_path / "gating")),
        confirm_mode=confirm_mode,
    )
```

Append:

```python
# ── chat-confirm mode ─────────────────────────────────────────────────
def test_chat_mode_target_echo_executes_and_audits(tmp_path):
    g = _gate(tmp_path, enabled=True, confirm_mode="chat")
    result = g.execute(
        target="web-01", actor="james", token="web-01", run=lambda: "ok"
    )
    assert result == "ok"
    entry = json.loads((tmp_path / "a.log").read_text().strip())
    assert entry["method"] == "chat-confirm"
    assert entry["token_ref"]  # action|target key prefix, non-empty


def test_chat_mode_wrong_echo_denied(tmp_path):
    g = _gate(tmp_path, enabled=True, confirm_mode="chat")
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token="web-99", run=lambda: "ok")


def test_chat_mode_still_accepts_a_valid_token(tmp_path):
    # chat-confirm is additive: the token path must still work in chat mode.
    g = _gate(tmp_path, enabled=True, confirm_mode="chat")
    tok = g.token_store.issue("defender.isolate_host", "web-01")
    g.execute(target="web-01", actor="james", token=tok, run=lambda: "ok")
    entry = json.loads((tmp_path / "a.log").read_text().strip())
    assert entry["method"] == "token"


def test_target_echo_rejected_in_token_mode(tmp_path):
    # No cross-mode leak: passing the target as the "token" in token mode
    # falls through to TokenStore.consume and denies.
    g = _gate(tmp_path, enabled=True, confirm_mode="token")
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token="web-01", run=lambda: "ok")


def test_chat_mode_flag_off_denies_even_with_echo(tmp_path):
    g = _gate(tmp_path, enabled=False, confirm_mode="chat")
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token="web-01", run=lambda: "ok")


def test_chat_mode_no_token_still_returns_intent_path(tmp_path):
    # With neither token nor echo, chat mode denies exactly like token mode
    # (the tool short-circuit returns intent before calling execute).
    g = _gate(tmp_path, enabled=True, confirm_mode="chat")
    with pytest.raises(GateDenied):
        g.execute(target="web-01", actor="james", token=None, run=lambda: "ok")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest core/tests/test_gating.py -v -k "chat_mode or token_mode"`
Expected: FAIL — `TypeError: ... unexpected keyword argument 'confirm_mode'`

- [ ] **Step 3: Implement in `core/f0_sectools_core/gating/actions.py`**

`GatedAction.__init__` gains the field:

```python
    def __init__(
        self,
        name: str,
        enabled: bool,
        audit: AuditLog,
        token_store: TokenStore,
        approvals: ApprovalStore | None = None,
        confirm_mode: str = "token",
    ) -> None:
        self.name = name
        self.enabled = enabled
        self.audit = audit
        self.token_store = token_store
        self.approvals = approvals if approvals is not None else ApprovalStore()
        self.confirm_mode = confirm_mode
```

`_authorize` gains one branch (right after the flag check, before the token branch):

```python
    def _authorize(self, target: str, token: str | None) -> str:
        if not self.enabled:
            raise GateDenied(
                f"Action '{self.name}' is disabled. Set the platform write flag to enable it."
            )
        if self.confirm_mode == "chat" and token is not None and token == target:
            # Chat-confirm: the operator replied "approved" and the model
            # echoed the exact target back. Not forge-resistant (opt-in only).
            return "chat-confirm"
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
```

`_audit` ref rule extends to chat-confirm:

```python
    def _audit(self, target: str, actor: str, token: str | None, method: str) -> None:
        ref = (
            ApprovalStore._key(self.name, target)[:16]
            if method in ("approval", "chat-confirm")
            else None
        )
        self.audit.record(self.name, target, actor, token or "", method=method, ref=ref)
```

- [ ] **Step 4: Run the full core suite, lint, type-check**

Run: `uv run pytest core -v && uv run ruff check core && uv run mypy .`
Expected: all PASS (every pre-existing token/approval test green), clean

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/gating/actions.py core/tests/test_gating.py
git commit -m "feat(gating): additive chat-confirm mode in GatedAction"
```

---

### Task 2: `ProjectAchillesConfig.confirm_mode` + validation

**Files:**
- Modify: `core/f0_sectools_core/auth/config.py` (`ProjectAchillesConfig` dataclass + `from_env`)
- Test: `core/tests/test_config.py` (append)

**Interfaces:**
- Produces: `ProjectAchillesConfig.confirm_mode: str = "token"`, parsed from `PROJECTACHILLES_CONFIRM_MODE`, validated to `{"token","chat"}`.

- [ ] **Step 1: Write the failing tests** — append to `core/tests/test_config.py`:

```python
def test_projectachilles_confirm_mode_defaults_token():
    env = {
        "PROJECTACHILLES_BASE_URL": "https://tpsgl.projectachilles.io",
        "PROJECTACHILLES_API_KEY": "pa_x",
    }
    assert ProjectAchillesConfig.from_env(env=env).confirm_mode == "token"


def test_projectachilles_confirm_mode_chat_parsed():
    env = {
        "PROJECTACHILLES_BASE_URL": "https://tpsgl.projectachilles.io",
        "PROJECTACHILLES_API_KEY": "pa_x",
        "PROJECTACHILLES_CONFIRM_MODE": "chat",
    }
    assert ProjectAchillesConfig.from_env(env=env).confirm_mode == "chat"


def test_projectachilles_confirm_mode_invalid_raises():
    env = {
        "PROJECTACHILLES_BASE_URL": "https://tpsgl.projectachilles.io",
        "PROJECTACHILLES_API_KEY": "pa_x",
        "PROJECTACHILLES_CONFIRM_MODE": "yolo",
    }
    with pytest.raises(ValueError):
        ProjectAchillesConfig.from_env(env=env)
```

(`pytest` is already imported in this test file.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest core/tests/test_config.py -v -k confirm_mode`
Expected: FAIL — `AttributeError: 'ProjectAchillesConfig' object has no attribute 'confirm_mode'`

- [ ] **Step 3: Implement in `core/f0_sectools_core/auth/config.py`**

Add the field to the dataclass (after `allow_write`):

```python
    allow_write: bool = False
    confirm_mode: str = "token"
```

In `from_env`, after the `allow_write` line, add validation and pass it through:

```python
        allow_write = env.get(f"{prefix}_ALLOW_WRITE", "false").strip().lower() in _TRUE
        confirm_mode = env.get(f"{prefix}_CONFIRM_MODE", "token").strip().lower()
        if confirm_mode not in ("token", "chat"):
            raise ValueError(
                f"{prefix}_CONFIRM_MODE must be 'token' or 'chat', got '{confirm_mode}'"
            )
        return cls(
            base_url=env[required["base_url"]].rstrip("/"),
            api_key=env[required["api_key"]],
            verify_tls=verify,
            allow_write=allow_write,
            confirm_mode=confirm_mode,
        )
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest core/tests/test_config.py -v && uv run ruff check core && uv run mypy .`
Expected: all PASS, clean

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/auth/config.py core/tests/test_config.py
git commit -m "feat(config): PROJECTACHILLES_CONFIRM_MODE (token|chat, validated)"
```

---

### Task 3: pa-actions wiring — `_gate` mode + mode-aware `_intent`

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py` (`_gate`)
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (`_intent` + its 4 call sites)
- Test: `servers/projectachilles-actions-mcp/tests/test_run_test.py` (update `_gate` fixture; append chat-mode tests)

**Interfaces:**
- Consumes: Task 1 `GatedAction(confirm_mode=...)`, Task 2 `cfg.confirm_mode`.

- [ ] **Step 1: Update the test fixture and write failing tests**

In `servers/projectachilles-actions-mcp/tests/test_run_test.py`, update the `_gate` helper to take a mode (keeps existing calls working) and set `confirm_mode`:

```python
def _gate(tmp_path, enabled: bool = True, confirm_mode: str = "token") -> GatedAction:
    return GatedAction(
        "projectachilles.run_test",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "audit.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
        approvals=ApprovalStore(str(tmp_path / "gating")),
        confirm_mode=confirm_mode,
    )
```

Append:

```python
@pytest.mark.asyncio
async def test_run_test_chat_mode_intent_text(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        router.post(f"{BASE}/api/agent/admin/tasks")
        gate = _gate(tmp_path, confirm_mode="chat")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, gate, UUID, "web-01")
    summary = findings[0].recommended_action.summary
    assert "approved" in summary.lower()
    assert TARGET in summary  # the model is told to echo this exact target


@pytest.mark.asyncio
async def test_run_test_chat_echo_executes(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(201, json={"data": {"task_ids": ["task-1"]}})
        )
        gate = _gate(tmp_path, confirm_mode="chat")
        async with ProjectAchillesClient(_cfg()) as pa:
            # The model echoes the target string as the confirmation.
            findings = await run_test(pa, gate, UUID, "web-01", TARGET)
    assert post.call_count == 1
    assert "Action completed" in findings[0].title
    entry = json.loads((tmp_path / "audit.log").read_text().strip())
    assert entry["method"] == "chat-confirm"


@pytest.mark.asyncio
async def test_run_test_chat_wrong_echo_still_denied(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        gate = _gate(tmp_path, confirm_mode="chat")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, gate, UUID, "web-01", f"{UUID}@wrong-host")
    assert post.called is False
    assert "not taken" in findings[0].title
```

(`TARGET` and `import json` already exist in this test file from the approval-flow tasks.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_run_test.py -v -k chat`
Expected: FAIL — `test_run_test_chat_mode_intent_text` fails (summary lacks "approved"); `chat_echo_executes` fails (wrong-token deny, no POST).

- [ ] **Step 3: Implement**

In `server.py`, `_gate` passes the mode:

```python
def _gate(name: str, cfg: ProjectAchillesConfig) -> GatedAction:
    return GatedAction(
        name,
        enabled=cfg.allow_write,
        audit=AuditLog(os.environ.get("PROJECTACHILLES_AUDIT_LOG_PATH") or None),
        token_store=TokenStore(),
        confirm_mode=cfg.confirm_mode,
    )
```

In `tools.py`, make `_intent` mode-aware. Change its signature to accept the mode and branch the summary:

```python
def _intent(
    action_name: str,
    target: str,
    title: str,
    entity: Entity | None,
    evidence: list[Evidence],
    confirm_mode: str = "token",
) -> Finding:
    short = action_name.split(".")[-1]
    if confirm_mode == "chat":
        summary = (
            "To execute: the operator replies 'approved' in the chat, then you "
            "call this tool again with confirmation_token set to the exact "
            f'target "{target}".'
        )
    else:
        summary = (
            "To execute: an operator approves this action in their "
            "confirm_action.py --watch terminal, then you call this tool again "
            "with the SAME arguments.\n"
            "Token fallback: python scripts/confirm_action.py "
            f'{short} "{target}" --platform projectachilles\n'
            "then pass the printed confirmation_token."
        )
    return Finding(
        source=_SOURCE,
        finding_type=FindingType.action,
        severity=Severity.high,
        title=f"Pending action: {title} (requires confirmation)",
        entity=entity,
        evidence=[*evidence, Evidence(key="confirmation_target", value=target)],
        recommended_action=RecommendedAction(
            summary=summary,
            gated_action=action_name,
            confidence="high",
        ),
    )
```

Then update the 4 call sites to pass `gate.confirm_mode`:
- `run_test` (~line 132): the `_intent(...)` block — add `confirm_mode=gate.confirm_mode` as the final argument.
- `schedule_test` (~line 295): same — add `confirm_mode=gate.confirm_mode`.
- `set_schedule_status` (~line 380): `return [_intent(gate.name, target, f"{verb} schedule {sid}", entity, evidence, gate.confirm_mode)]`
- `cancel_task` (~line 437): `return [_intent(gate.name, target, f"cancel task {tid}", entity, evidence, gate.confirm_mode)]`

(For run_test/schedule_test which use the multi-line `_intent(` form with `gate.name` as the first arg, add `confirm_mode=gate.confirm_mode` on its own line before the closing `)`.)

- [ ] **Step 4: Run the pa-actions suite, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy .`
Expected: all PASS — including every pre-existing token-mode intent-text and negative-space assertion — clean

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py servers/projectachilles-actions-mcp/tests/test_run_test.py
git commit -m "feat(pa-actions): wire chat-confirm mode into the gate and intent text"
```

---

### Task 4: Docs — Rule 1 amendment + gated section + .env + skill + README

**Files:**
- Modify: `CLAUDE.md` (Critical Rule 1; Gated Write Actions section)
- Modify: `servers/projectachilles-mcp/.env.projectachilles.example`
- Modify: `skills/projectachilles/run-validation-test/SKILL.md`
- Modify: `servers/projectachilles-actions-mcp/README.md`

- [ ] **Step 1: Amend CLAUDE.md Critical Rule 1**

Replace Rule 1's text with the two-mode form (keep the numbering and the surrounding rules intact):

```markdown
1. **Read-only by default.** Every tool that queries a platform is read-only. Any tool that *changes state* on a live platform (isolate host, disable user, quarantine file, close incident) is a **gated write action** — see [Gated Write Actions](#gated-write-actions). It MUST require an explicit config flag AND per-action human confirmation, in one of two modes: **(a) forge-resistant** — a single-use confirmation token or a watcher approval delivered out-of-band on a channel the model cannot read; this is the default and the **only** permitted mode for destructive or irreversible actions. **(b) chat-confirm** — an opt-in, per-platform mode (off by default) where the operator's in-chat "approved" is the confirmation; it is convenient for supervised, reversible actions but is **not** forge-resistant (a misaligned model could fabricate it), so it is never used for destructive actions.
```

- [ ] **Step 2: Expand the Gated Write Actions section**

Add a subsection describing the three confirmation surfaces (watcher, token, chat-confirm) and the honest caveat. Read the section first and match its format; the new content states: chat-confirm is enabled by `PROJECTACHILLES_CONFIRM_MODE=chat` (PA only today), the operator types "approved" and the model re-calls echoing the target, execution audits `method=chat-confirm`, and it must not be enabled for destructive actions because it is model-forgeable.

- [ ] **Step 3: `.env.projectachilles.example`**

Read the file, then add near the `PROJECTACHILLES_ALLOW_WRITE` block:

```
# Confirmation mode for gated writes (projectachilles-actions server):
#   token (default) — forge-resistant: approve in `confirm_action.py --watch`
#                     or paste a single-use token. The model cannot fabricate it.
#   chat            — LOW-FRICTION, OPT-IN: you just type "approved" in the chat
#                     and the model re-runs the action. Convenient for supervised
#                     validation runs, but NOT forge-resistant — only enable it
#                     when you are watching every turn. Never for destructive actions.
# PROJECTACHILLES_CONFIRM_MODE=token
```

- [ ] **Step 4: `run-validation-test` skill**

Read the SKILL.md Procedure; add a chat-confirm variant beside the watcher steps: when `PROJECTACHILLES_CONFIRM_MODE=chat`, after the intent finding the operator simply replies "approved" and the agent re-calls the same tool passing `confirmation_token` = the `confirmation_target` shown. Keep the frontmatter (description ≤60 chars) untouched. Run `uv run pytest skills/test_skills_valid.py` after.

- [ ] **Step 5: pa-actions README**

Read the README's Setup section; add a one-paragraph note on the two confirmation modes with the same caveat.

- [ ] **Step 6: Full verification**

Run: `uv run pytest && uv run ruff check . && uv run mypy .`
Expected: ALL PASS, clean. `git status --short` shows no real `.env*` staged.

- [ ] **Step 7: Commit**

```bash
git add CLAUDE.md servers/projectachilles-mcp/.env.projectachilles.example skills/projectachilles/run-validation-test/SKILL.md servers/projectachilles-actions-mcp/README.md
git commit -m "docs(gating): document chat-confirm mode and amend Critical Rule 1"
```

---

## Plan Self-Review (done at write time)

- **Spec coverage:** confirm_mode field + additive `_authorize` branch + audit method (T1); config field + validation (T2); server `_gate` wiring + mode-aware `_intent` text at all 4 sites (T3); Rule 1 amendment + gated section + .env + skill + README (T4). Spec milestone 5 (live pi check) is user-gated — intentionally not a task.
- **Type consistency:** `confirm_mode: str` default `"token"` everywhere (`GatedAction`, `ProjectAchillesConfig`, both `_gate` helpers, `_intent`); audit method literal `"chat-confirm"` matches between `_authorize`/`_audit` and the tests; echo rule `token == target` identical in code and tests.
- **Cross-mode safety pinned by test:** `test_target_echo_rejected_in_token_mode` proves a target-echo does nothing in the default mode; `test_chat_mode_flag_off_denies_even_with_echo` proves the flag stays outermost.
- **Known judgment point:** the 4 `_intent` call-site line numbers may drift a few lines — anchor on the quoted call forms, not the numbers.
