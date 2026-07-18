# ProjectAchilles Actions Server (Gated Writes) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A second thin PA MCP server (`f0-pa-actions`, 6 tools) that runs/schedules/pauses/cancels ProjectAchilles validation tests behind the `core/gating` flag + single-use-token + audit gate.

**Architecture:** New workspace member `servers/projectachilles-actions-mcp/` (package `f0_pa_actions_mcp`) importing `core/` only — client (get/post/patch), pre-gate resolution (`resolve.py`), error mapping, 4 gated + 2 read tools, FastMCP registration with redaction at the boundary. The existing read server and `core/` are NOT modified (except docs/evals bookkeeping).

**Tech Stack:** Python 3.11+, httpx, MCP Python SDK (FastMCP), pytest + respx + pytest-asyncio, uv workspace.

**Spec:** `docs/superpowers/specs/2026-07-18-projectachilles-actions-design.md` (committed 8059246). Branch: `feat/pa-actions-mcp` (already checked out).

## Global Constraints

- **No `core/` changes.** Gating, schema, redaction, paging are imported as-is.
- **Read server untouched:** nothing under `servers/projectachilles-mcp/` changes except its `.env.projectachilles.example` comment block (Task 10).
- **Every failure becomes a finding, never an exception** reaching the agent.
- **Redact at the boundary:** `server.py` returns `redact_obj(f.model_dump())` for every finding.
- **Enum params are `Literal[...]` from day one** (exact literals in Task 8).
- **Token target strings (verbatim, spec §Gating Flow):** run_test/schedule_test → `<test_uuid>@<hostname>`; set_schedule_status → `<schedule_id>:<status>`; cancel_task → `<task_id>`. Gate action names: `projectachilles.run_test`, `projectachilles.schedule_test`, `projectachilles.set_schedule_status`, `projectachilles.cancel_task`.
- **Resolution/validation runs BEFORE the gate** — a resolution failure must never consume a token or hit a write endpoint.
- **Timezone is always `"UTC"`** in v1 schedule payloads.
- **Weekly day-of-week mapping:** sunday=0, monday=1, … saturday=6 (verified against PA `dayOfWeekInTimezone`).
- **Backend wire facts:** client prepends `/api`; test detail at `GET /browser/tests/{uuid}` → `{"test": {...camelCase...}}`; build info at `GET /tests/builds/{uuid}` → `{"data": {"exists": bool, "filename": str}}` (not-built is HTTP 200 + `exists:false`, NOT 404); agents at `GET /agent/admin/agents` → `{"data": {"agents": [{id, org_id, hostname, ...}]}}`; task create `POST /agent/admin/tasks` → `{"data": {"task_ids": [...]}}`; schedule create `POST /agent/admin/schedules` → `{"data": {schedule}}`; `PATCH /agent/admin/schedules/{id}`; `POST /agent/admin/tasks/{id}/cancel`; `GET /agent/admin/tasks/{id}`; `GET /agent/admin/schedules`.
- **Task metadata is snake_case and all-fields-required-if-present** (backend Zod `TaskTestMetadataSchema` has no per-field optionality): category, subcategory, severity, techniques, tactics, threat_actor, target, complexity, tags, score (nullable), integrations.
- **NO `tests/__init__.py`** in the new server's tests dir (importlib package-name collision — bit us in PR #24).
- **Commits:** conventional style, `git add` specific files (never `-A`), NO backticks in `-m` strings. Do not push.
- **Verification for every task:** the named tests pass, plus `uv run ruff check servers/projectachilles-actions-mcp` and `uv run mypy servers/projectachilles-actions-mcp/f0_pa_actions_mcp` are clean.

---

### Task 1: Scaffold + client (get/post/patch)

**Files:**
- Create: `servers/projectachilles-actions-mcp/pyproject.toml`
- Create: `servers/projectachilles-actions-mcp/README.md`
- Create: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/__init__.py`
- Create: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/client.py`
- Test: `servers/projectachilles-actions-mcp/tests/test_client.py`

**Interfaces:**
- Consumes: `ProjectAchillesConfig` from `f0_sectools_core.auth.config` (exists; fields `base_url`, `api_key`, `verify_tls`, `allow_write`).
- Produces: `ProjectAchillesClient` with `async get(path, params=None) -> dict[str, Any]`, `async post(path, json=None) -> dict[str, Any]`, `async patch(path, json=None) -> dict[str, Any]`, async-context-manager; `ProjectAchillesError(status: int, message: str)`. All later tasks call these.

- [ ] **Step 1: Write pyproject.toml**

```toml
[project]
name = "f0-projectachilles-actions-mcp"
version = "0.0.1"
description = "f0_sectools MCP server for ProjectAchilles gated write actions — run/schedule/pause/cancel validation tests."
readme = "README.md"
requires-python = ">=3.11"
license = { text = "Apache-2.0" }
authors = [{ name = "F0RT1KA Contributors" }]
dependencies = [
    "f0-sectools-core",
    "mcp>=1.0",
    "httpx>=0.27",
]

[project.scripts]
f0-projectachilles-actions-mcp = "f0_pa_actions_mcp.server:main"

[tool.uv.sources]
f0-sectools-core = { workspace = true }

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["f0_pa_actions_mcp"]
```

- [ ] **Step 2: Write README.md**

```markdown
# f0-pa-actions — ProjectAchilles gated write actions (MCP server)

Companion to `servers/projectachilles-mcp/` (read-only). This server exposes
the **write** side of the validation loop, every write gated by
`core/gating` (operator flag + single-use confirmation token + local audit):

| Tool | Type |
|---|---|
| `run_test(test_id, hostname)` | GATED — execute a validation test now |
| `schedule_test(test_id, hostname, schedule, run_time, …)` | GATED — recurring/once schedule (UTC) |
| `set_schedule_status(schedule_id, status)` | GATED — pause/resume |
| `cancel_task(task_id)` | GATED — cancel a pending run |
| `list_schedules(status)` | read |
| `get_task_status(task_id)` | read |

## Setup

Shares `.env.projectachilles` with the read server (same platform, same
credential file). Two extra requirements for writes:

1. The `pa_` API key must be **read-write scope** (a read-only key 403s on
   every write — you get a permission finding telling you so).
2. `PROJECTACHILLES_ALLOW_WRITE=true` must be set.

Executing a gated action is two-step: call the tool without
`confirmation_token` to get the fully-resolved intent (and the exact target
string), then run `python scripts/confirm_action.py <action> "<target>"
--platform projectachilles` and call again with the printed token. Tokens
are single-use, expire in 15 minutes, and are bound to (action, target).

## Run

    uv run f0-projectachilles-actions-mcp
```

- [ ] **Step 3: Write `f0_pa_actions_mcp/__init__.py`**

```python
"""f0_sectools ProjectAchilles actions MCP server (gated writes)."""
```

- [ ] **Step 4: Write the failing client test**

`servers/projectachilles-actions-mcp/tests/test_client.py` (no `__init__.py` in tests/):

```python
"""Client tests: /api prefixing, error wrapping, post/patch bodies."""
from __future__ import annotations

import httpx
import pytest
import respx
from f0_sectools_core.auth.config import ProjectAchillesConfig

from f0_pa_actions_mcp.client import ProjectAchillesClient, ProjectAchillesError

BASE = "https://org.agent.example.com"


def _cfg(**kw) -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test", **kw)


@pytest.mark.asyncio
async def test_get_prefixes_api_and_returns_json():
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(200, json={"success": True, "data": []})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            d = await pa.get("/agent/admin/schedules")
    assert d == {"success": True, "data": []}


@pytest.mark.asyncio
async def test_post_sends_json_body():
    with respx.mock(assert_all_called=True) as router:
        route = router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(201, json={"success": True, "data": {"task_ids": ["t1"]}})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            d = await pa.post("/agent/admin/tasks", json={"org_id": "o1"})
    assert d["data"]["task_ids"] == ["t1"]
    import json as _json
    assert _json.loads(route.calls[0].request.content) == {"org_id": "o1"}


@pytest.mark.asyncio
async def test_patch_sends_json_body():
    with respx.mock(assert_all_called=True) as router:
        route = router.patch(f"{BASE}/api/agent/admin/schedules/s1").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {"id": "s1"}})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            d = await pa.patch("/agent/admin/schedules/s1", json={"status": "paused"})
    assert d["data"]["id"] == "s1"
    import json as _json
    assert _json.loads(route.calls[0].request.content) == {"status": "paused"}


@pytest.mark.asyncio
async def test_error_status_raises_wrapped_error_with_message():
    with respx.mock() as router:
        router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(403, json={"error": "Missing permission"})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ProjectAchillesError) as ei:
                await pa.post("/agent/admin/tasks", json={})
    assert ei.value.status == 403
    assert "Missing permission" in ei.value.message


@pytest.mark.asyncio
async def test_empty_body_returns_empty_dict():
    with respx.mock() as router:
        router.post(f"{BASE}/api/agent/admin/tasks/t1/cancel").mock(
            return_value=httpx.Response(200)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            d = await pa.post("/agent/admin/tasks/t1/cancel")
    assert d == {}
```

- [ ] **Step 5: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_client.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_pa_actions_mcp.client'` (or the package isn't installed yet — run `uv sync --all-packages` first so the new member is installed, THEN expect the ModuleNotFoundError on client).

- [ ] **Step 6: Write `f0_pa_actions_mcp/client.py`**

```python
"""Thin async client for the ProjectAchilles REST API (reads + gated writes).

Auth is a static `Authorization: Bearer pa_…` key. Writes additionally require
the key to be read-write scope — a read-only key produces HTTP 403, which the
tools map to a permission finding. Errors are raised as ProjectAchillesError
with a redacted message; the tools map them to graceful findings.
"""
from __future__ import annotations

from typing import Any

import httpx
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.redaction.redact import redact_text


class ProjectAchillesError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = redact_text(message)
        super().__init__(f"ProjectAchilles HTTP {status}: {self.message}")


class ProjectAchillesClient:
    def __init__(self, config: ProjectAchillesConfig) -> None:
        self.base_url = config.base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            verify=config.verify_tls,
            timeout=60.0,
            headers={"Authorization": f"Bearer {config.api_key}"},
        )

    async def __aenter__(self) -> ProjectAchillesClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        resp = await self._client.request(
            method, f"{self.base_url}/api{path}", params=params, json=json
        )
        if resp.status_code // 100 != 2:
            try:
                body = resp.json()
                msg = body.get("error") or body.get("message") or resp.text
            except Exception:
                msg = resp.text
            raise ProjectAchillesError(resp.status_code, str(msg) or "request failed")
        out = resp.json() if resp.content else {}
        return out if isinstance(out, dict) else {"data": out}

    async def get(
        self, path: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._request("GET", path, params=params)

    async def post(
        self, path: str, json: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._request("POST", path, json=json)

    async def patch(
        self, path: str, json: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._request("PATCH", path, json=json)
```

- [ ] **Step 7: Sync workspace and run tests**

Run: `uv sync --all-packages && uv run pytest servers/projectachilles-actions-mcp/tests/test_client.py -v`
Expected: 5 PASS

- [ ] **Step 8: Lint + type-check**

Run: `uv run ruff check servers/projectachilles-actions-mcp && uv run mypy servers/projectachilles-actions-mcp/f0_pa_actions_mcp`
Expected: clean

- [ ] **Step 9: Commit**

```bash
git add servers/projectachilles-actions-mcp uv.lock
git commit -m "feat(pa-actions): scaffold actions server with get/post/patch client"
```

---

### Task 2: Error mapping (errors.py)

**Files:**
- Create: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/errors.py`
- Test: `servers/projectachilles-actions-mcp/tests/test_errors.py`

**Interfaces:**
- Consumes: `ProjectAchillesError` from Task 1; `Finding`, `FindingType`, `Severity`, `Evidence`, `RecommendedAction` from `f0_sectools_core.schema.findings` (incl. classmethods `Finding.permission_missing`, `Finding.rate_limited`, `Finding.api_unavailable`).
- Produces: `map_pa_error(e: Exception, capability: str) -> Finding | None` — returns a graceful finding for 401/403/429/502/503/504 and for 400/404/409/422 (a generic "rejected" finding carrying the backend message), else `None` (caller re-raises).

- [ ] **Step 1: Write the failing test**

`servers/projectachilles-actions-mcp/tests/test_errors.py`:

```python
"""Error-to-finding mapping tests, including the write-scope 403 hint."""
from __future__ import annotations

from f0_pa_actions_mcp.client import ProjectAchillesError
from f0_pa_actions_mcp.errors import map_pa_error
from f0_sectools_core.schema.findings import FindingType, Severity


def test_401_maps_to_auth_posture_finding():
    f = map_pa_error(ProjectAchillesError(401, "bad key"), "run test")
    assert f is not None
    assert f.finding_type == FindingType.posture
    assert "authentication failed" in f.title.lower()


def test_403_names_read_write_scope():
    f = map_pa_error(ProjectAchillesError(403, "Missing permission"), "run test")
    assert f is not None
    assert "read-write" in f.title or "read-write" in f.recommended_action.summary


def test_429_maps_to_rate_limited():
    f = map_pa_error(ProjectAchillesError(429, "slow down"), "run test")
    assert f is not None
    assert "rate limited" in f.title.lower()


def test_503_maps_to_unavailable():
    f = map_pa_error(ProjectAchillesError(503, "upstream"), "run test")
    assert f is not None
    assert "unavailable" in f.title.lower()


def test_400_maps_to_rejected_finding_with_message():
    f = map_pa_error(ProjectAchillesError(400, "task already terminal"), "cancel task")
    assert f is not None
    assert f.severity == Severity.info
    assert any("task already terminal" in ev.value for ev in f.evidence)


def test_404_maps_to_rejected_finding():
    f = map_pa_error(ProjectAchillesError(404, "Schedule not found"), "pause schedule")
    assert f is not None
    assert "404" in f.title


def test_unknown_status_returns_none():
    assert map_pa_error(ProjectAchillesError(418, "teapot"), "x") is None


def test_non_pa_error_returns_none():
    assert map_pa_error(ValueError("nope"), "x") is None
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_errors.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_pa_actions_mcp.errors'`

- [ ] **Step 3: Write `f0_pa_actions_mcp/errors.py`**

```python
"""Map ProjectAchilles HTTP errors to graceful findings (write-aware)."""
from __future__ import annotations

from f0_sectools_core.schema.findings import (
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from .client import ProjectAchillesError


def map_pa_error(e: Exception, capability: str) -> Finding | None:
    """Return a graceful finding for known PA errors, else None (caller re-raises)."""
    if not isinstance(e, ProjectAchillesError):
        return None
    if e.status == 401:
        return Finding(
            source="projectachilles",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"ProjectAchilles authentication failed — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary="Check PROJECTACHILLES_BASE_URL and PROJECTACHILLES_API_KEY "
                "(a valid, non-revoked pa_ key).",
                confidence="high",
            ),
        )
    if e.status == 403:
        return Finding.permission_missing(
            "projectachilles", "a read-write-scope pa_ API key", capability
        )
    if e.status == 429:
        return Finding.rate_limited("projectachilles", capability)
    if e.status in (502, 503, 504):
        return Finding.api_unavailable("projectachilles", capability, e.status)
    if e.status in (400, 404, 409, 422):
        return Finding(
            source="projectachilles",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"ProjectAchilles rejected the request (HTTP {e.status}) — {capability}",
            evidence=[Evidence(key="error", value=e.message)],
            recommended_action=RecommendedAction(
                summary="Check the id/arguments and retry. If a confirmation token "
                "was consumed, issue a fresh one.",
                confidence="high",
            ),
        )
    return None
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_errors.py -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy servers/projectachilles-actions-mcp/f0_pa_actions_mcp`
Expected: 8 PASS, clean

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/errors.py servers/projectachilles-actions-mcp/tests/test_errors.py
git commit -m "feat(pa-actions): map PA errors to findings with write-scope 403 hint"
```

---

### Task 3: Pre-gate resolution (resolve.py)

**Files:**
- Create: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/resolve.py`
- Test: `servers/projectachilles-actions-mcp/tests/test_resolve.py`

**Interfaces:**
- Consumes: client + errors from Tasks 1–2.
- Produces (all used by Tasks 4–5):
  - `class ResolveFailed(Exception)` with attribute `finding: Finding`.
  - `async resolve_test(pa, test_id: str) -> dict[str, Any]` → `{"test_uuid": str, "test_name": str, "metadata": dict}` (metadata is the full snake_case TaskTestMetadata block).
  - `async resolve_build(pa, test_uuid: str) -> str` → the binary filename.
  - `async resolve_agent(pa, hostname: str) -> dict[str, str]` → `{"agent_id", "org_id", "hostname"}` (hostname echoed with the AGENT's casing).
  - `guidance(title: str, summary: str) -> Finding` (posture/info helper, reused by Task 5's schedule validation).

- [ ] **Step 1: Write the failing test**

`servers/projectachilles-actions-mcp/tests/test_resolve.py`:

```python
"""Resolution tests: test/build/agent lookups fail gracefully BEFORE the gate."""
from __future__ import annotations

import httpx
import pytest
import respx
from f0_sectools_core.auth.config import ProjectAchillesConfig

from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.resolve import (
    ResolveFailed,
    resolve_agent,
    resolve_build,
    resolve_test,
)

BASE = "https://org.agent.example.com"
UUID = "3f2a9c10-1111-4222-8333-444455556666"

TEST_RECORD = {
    "uuid": UUID,
    "name": "Brute Force SSH",
    "category": "credential-access",
    "subcategory": "brute-force",
    "severity": "high",
    "techniques": ["T1110"],
    "tactics": ["TA0006"],
    "threatActor": "APT29",
    "target": ["linux"],
    "complexity": "low",
    "tags": ["ssh"],
    "score": None,
    "integrations": [],
}


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test")


@pytest.mark.asyncio
async def test_resolve_test_returns_uuid_name_and_snake_case_metadata():
    with respx.mock() as router:
        router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
            return_value=httpx.Response(200, json={"test": TEST_RECORD})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            t = await resolve_test(pa, UUID)
    assert t["test_uuid"] == UUID
    assert t["test_name"] == "Brute Force SSH"
    md = t["metadata"]
    assert md["threat_actor"] == "APT29"          # camelCase -> snake_case
    assert md["techniques"] == ["T1110"]
    assert md["score"] is None
    # Zod TaskTestMetadataSchema requires ALL keys when metadata is present:
    for key in (
        "category", "subcategory", "severity", "techniques", "tactics",
        "threat_actor", "target", "complexity", "tags", "score", "integrations",
    ):
        assert key in md


@pytest.mark.asyncio
async def test_resolve_test_non_uuid_fails_with_guidance():
    async with ProjectAchillesClient(_cfg()) as pa:
        with pytest.raises(ResolveFailed) as ei:
            await resolve_test(pa, "brute force")
    assert "uuid" in ei.value.finding.title.lower()


@pytest.mark.asyncio
async def test_resolve_test_404_fails_with_not_found_finding():
    with respx.mock() as router:
        router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_test(pa, UUID)
    assert "not found" in ei.value.finding.title.lower()


@pytest.mark.asyncio
async def test_resolve_build_returns_filename():
    with respx.mock() as router:
        router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
            return_value=httpx.Response(
                200,
                json={"success": True, "data": {"exists": True, "filename": "brute_force_ssh"}},
            )
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            assert await resolve_build(pa, UUID) == "brute_force_ssh"


@pytest.mark.asyncio
async def test_resolve_build_not_built_is_200_exists_false():
    with respx.mock() as router:
        router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {"exists": False}})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_build(pa, UUID)
    assert "not built" in ei.value.finding.title.lower()


AGENTS = {
    "success": True,
    "data": {
        "agents": [
            {"id": "ag-1", "org_id": "org-1", "hostname": "web-01", "status": "online"},
            {"id": "ag-2", "org_id": "org-1", "hostname": "db-01", "status": "online"},
        ]
    },
}


@pytest.mark.asyncio
async def test_resolve_agent_exact_case_insensitive_match():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=AGENTS)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            a = await resolve_agent(pa, "WEB-01")
    assert a == {"agent_id": "ag-1", "org_id": "org-1", "hostname": "web-01"}


@pytest.mark.asyncio
async def test_resolve_agent_no_match_lists_guidance():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=AGENTS)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_agent(pa, "gone-99")
    assert "gone-99" in ei.value.finding.title


@pytest.mark.asyncio
async def test_resolve_agent_ambiguous_lists_candidates():
    dup = {
        "success": True,
        "data": {"agents": [
            {"id": "ag-1", "org_id": "org-1", "hostname": "web-01"},
            {"id": "ag-9", "org_id": "org-1", "hostname": "web-01"},
        ]},
    }
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=dup)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_agent(pa, "web-01")
    ev = ei.value.finding.evidence
    assert {e.value for e in ev} >= {"ag-1", "ag-9"}


@pytest.mark.asyncio
async def test_resolve_agent_empty_hostname_guides():
    async with ProjectAchillesClient(_cfg()) as pa:
        with pytest.raises(ResolveFailed):
            await resolve_agent(pa, "  ")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_resolve.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_pa_actions_mcp.resolve'`

- [ ] **Step 3: Write `f0_pa_actions_mcp/resolve.py`**

```python
"""Pre-gate resolution: turn the model's (test_id, hostname) into the full
backend payload facts. Any failure raises ResolveFailed carrying a graceful
finding — resolution ALWAYS runs before the gate, so a bad input never burns
an operator confirmation token or touches a write endpoint.
"""
from __future__ import annotations

import re
from typing import Any

from f0_sectools_core.schema.findings import (
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from .client import ProjectAchillesError
from .errors import map_pa_error

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ResolveFailed(Exception):
    """Resolution/validation failure carrying the finding to return."""

    def __init__(self, finding: Finding) -> None:
        self.finding = finding
        super().__init__(finding.title)


def guidance(title: str, summary: str) -> Finding:
    return Finding(
        source="projectachilles",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=title,
        recommended_action=RecommendedAction(summary=summary, confidence="high"),
    )


def _mapped(e: Exception, capability: str) -> ResolveFailed:
    finding = map_pa_error(e, capability)
    if finding:
        return ResolveFailed(finding)
    raise e


def _task_metadata(t: dict[str, Any]) -> dict[str, Any]:
    # Backend Zod TaskTestMetadataSchema: optional as a whole, but if present
    # EVERY key must be present (no per-field optionality). snake_case on the
    # wire; the browser test record is camelCase (threatActor).
    return {
        "category": str(t.get("category") or ""),
        "subcategory": str(t.get("subcategory") or ""),
        "severity": str(t.get("severity") or ""),
        "techniques": list(t.get("techniques") or []),
        "tactics": list(t.get("tactics") or []),
        "threat_actor": str(t.get("threatActor") or ""),
        "target": list(t.get("target") or []),
        "complexity": str(t.get("complexity") or ""),
        "tags": list(t.get("tags") or []),
        "score": t.get("score"),
        "integrations": list(t.get("integrations") or []),
    }


async def resolve_test(pa: Any, test_id: str) -> dict[str, Any]:
    """test_id (UUID) -> {test_uuid, test_name, metadata}."""
    tid = test_id.strip()
    if not _UUID_RE.match(tid):
        raise ResolveFailed(
            guidance(
                f"test_id must be a test UUID, got '{tid or '(empty)'}'",
                "Look the test up first with find_tests/get_test on the "
                "ProjectAchilles read server, then pass its uuid.",
            )
        )
    try:
        resp = await pa.get(f"/browser/tests/{tid}")
    except ProjectAchillesError as e:
        if e.status == 404:
            raise ResolveFailed(
                guidance(
                    f"Test {tid} not found in the ProjectAchilles catalog",
                    "Verify the uuid with find_tests on the read server.",
                )
            ) from e
        raise _mapped(e, "test lookup") from e
    t = resp.get("test") if isinstance(resp, dict) else None
    if not isinstance(t, dict):
        raise ResolveFailed(
            guidance(
                f"Test {tid} not found in the ProjectAchilles catalog",
                "Verify the uuid with find_tests on the read server.",
            )
        )
    return {
        "test_uuid": str(t.get("uuid") or tid),
        "test_name": str(t.get("name") or ""),
        "metadata": _task_metadata(t),
    }


async def resolve_build(pa: Any, test_uuid: str) -> str:
    """test_uuid -> built binary filename. Not-built is HTTP 200 + exists:false."""
    try:
        resp = await pa.get(f"/tests/builds/{test_uuid}")
    except ProjectAchillesError as e:
        raise _mapped(e, "build lookup") from e
    d = resp.get("data") if isinstance(resp, dict) else None
    d = d if isinstance(d, dict) else {}
    if not d.get("exists") or not d.get("filename"):
        raise ResolveFailed(
            guidance(
                f"Test {test_uuid} is not built — cannot run or schedule it",
                "Build & sign the test in the ProjectAchilles console "
                "(Tests -> Build) first, then retry.",
            )
        )
    return str(d["filename"])


async def resolve_agent(pa: Any, hostname: str) -> dict[str, str]:
    """hostname (exact, case-insensitive) -> {agent_id, org_id, hostname}."""
    h = hostname.strip()
    if not h:
        raise ResolveFailed(
            guidance(
                "hostname is required",
                "Pass the exact agent hostname; list agents with list_agents "
                "on the read server.",
            )
        )
    try:
        resp = await pa.get("/agent/admin/agents", params={"limit": 200})
    except ProjectAchillesError as e:
        raise _mapped(e, "agent lookup") from e
    data = resp.get("data") if isinstance(resp, dict) else None
    agents = (data.get("agents") if isinstance(data, dict) else data) or []
    matches = [
        a for a in agents
        if isinstance(a, dict) and str(a.get("hostname", "")).lower() == h.lower()
    ]
    if not matches:
        raise ResolveFailed(
            guidance(
                f"No ProjectAchilles agent with hostname '{h}'",
                "Check the hostname with list_agents on the read server "
                "(exact match required).",
            )
        )
    if len(matches) > 1:
        raise ResolveFailed(
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Multiple agents match hostname '{h}' — ambiguous target",
                evidence=[
                    Evidence(key=str(a.get("hostname", "?")), value=str(a.get("id", "")))
                    for a in matches[:10]
                ],
                recommended_action=RecommendedAction(
                    summary="Disambiguate in the PA console; v1 targets exactly "
                    "one agent per call.",
                    confidence="high",
                ),
            )
        )
    a = matches[0]
    return {
        "agent_id": str(a.get("id") or ""),
        "org_id": str(a.get("org_id") or ""),
        "hostname": str(a.get("hostname") or h),
    }
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_resolve.py -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy servers/projectachilles-actions-mcp/f0_pa_actions_mcp`
Expected: 9 PASS, clean

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/resolve.py servers/projectachilles-actions-mcp/tests/test_resolve.py
git commit -m "feat(pa-actions): pre-gate resolution of test, build and agent"
```

---

### Task 4: Gate helpers + run_test (negative-space tests)

**Files:**
- Create: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py`
- Test: `servers/projectachilles-actions-mcp/tests/test_run_test.py`

**Interfaces:**
- Consumes: Tasks 1–3; `GatedAction`, `GateDenied`, `AuditLog`, `TokenStore` from `f0_sectools_core.gating.actions`.
- Produces:
  - `async run_test(pa, gate: GatedAction, test_id: str, hostname: str, confirmation_token: str = "", actor: str = "mcp-operator") -> list[Finding]`
  - Module helpers reused by Tasks 5–6: `_intent(action_name, target, title, entity, evidence) -> Finding`, `_refusal(action_name, target, exc) -> Finding`, `_after_gate_error(e, gate_name, target, capability) -> list[Finding]`.

- [ ] **Step 1: Write the failing test**

`servers/projectachilles-actions-mcp/tests/test_run_test.py`:

```python
"""run_test gate tests — most assertions are NEGATIVE SPACE (what did NOT happen)."""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore
from f0_sectools_core.schema.findings import FindingType

from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.tools import run_test

BASE = "https://org.agent.example.com"
UUID = "3f2a9c10-1111-4222-8333-444455556666"
TARGET = f"{UUID}@web-01"

TEST_RECORD = {
    "uuid": UUID, "name": "Brute Force SSH", "category": "credential-access",
    "subcategory": "brute-force", "severity": "high", "techniques": ["T1110"],
    "tactics": ["TA0006"], "threatActor": "APT29", "target": ["linux"],
    "complexity": "low", "tags": ["ssh"], "score": None, "integrations": [],
}
AGENTS = {"data": {"agents": [
    {"id": "ag-1", "org_id": "org-1", "hostname": "web-01", "status": "online"},
]}}
BUILD = {"data": {"exists": True, "filename": "brute_force_ssh"}}


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test", allow_write=True)


def _gate(tmp_path, enabled: bool = True) -> GatedAction:
    return GatedAction(
        "projectachilles.run_test",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "audit.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
    )


def _mock_reads(router) -> None:
    router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
        return_value=httpx.Response(200, json={"test": TEST_RECORD})
    )
    router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
        return_value=httpx.Response(200, json=BUILD)
    )
    router.get(f"{BASE}/api/agent/admin/agents").mock(
        return_value=httpx.Response(200, json=AGENTS)
    )


@pytest.mark.asyncio
async def test_no_token_returns_intent_and_no_write_call(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01")
    assert post.called is False                      # negative space
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == FindingType.action
    assert "Pending action" in f.title
    assert f.recommended_action.gated_action == "projectachilles.run_test"
    # The intent must print the exact target string for confirm_action.py:
    assert TARGET in f.recommended_action.summary
    assert "--platform projectachilles" in f.recommended_action.summary


@pytest.mark.asyncio
async def test_flag_off_refuses_and_no_write_call(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(
                pa, _gate(tmp_path, enabled=False), UUID, "web-01", token
            )
    assert post.called is False
    assert "not taken" in findings[0].title
    assert "PROJECTACHILLES_ALLOW_WRITE" in findings[0].recommended_action.summary


@pytest.mark.asyncio
async def test_wrong_target_token_refused(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", f"{UUID}@db-01")  # other host
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", token)
    assert post.called is False
    assert "not taken" in findings[0].title


@pytest.mark.asyncio
async def test_valid_token_executes_posts_payload_and_audits(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(201, json={"data": {"task_ids": ["task-1"]}})
        )
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", token)
    assert post.call_count == 1
    body = json.loads(post.calls[0].request.content)
    assert body["org_id"] == "org-1"
    assert body["agent_ids"] == ["ag-1"]
    assert body["test_uuid"] == UUID
    assert body["test_name"] == "Brute Force SSH"
    assert body["binary_name"] == "brute_force_ssh"
    assert body["metadata"]["threat_actor"] == "APT29"
    assert "Action completed" in findings[0].title
    assert any(ev.value == "task-1" for ev in findings[0].evidence)
    assert (tmp_path / "audit.log").exists()          # audit line written
    # single-use: same token again is refused
    with respx.mock() as router:
        _mock_reads(router)
        post2 = router.post(f"{BASE}/api/agent/admin/tasks")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings2 = await run_test(pa, _gate(tmp_path), UUID, "web-01", token)
    assert post2.called is False
    assert "not taken" in findings2[0].title


@pytest.mark.asyncio
async def test_resolution_failure_returns_finding_and_never_consults_gate(tmp_path):
    with respx.mock() as router:
        router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
            return_value=httpx.Response(404, json={"error": "nope"})
        )
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", token)
    assert post.called is False
    assert "not found" in findings[0].title.lower()
    # token NOT consumed by a resolution failure:
    assert TokenStore(str(tmp_path / "pending")).consume(
        "projectachilles.run_test", TARGET, token
    )


@pytest.mark.asyncio
async def test_platform_403_after_token_maps_to_permission_finding(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(403, json={"error": "Missing permission"})
        )
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", token)
    assert "read-write" in (
        findings[0].title + findings[0].recommended_action.summary
    )
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_run_test.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_pa_actions_mcp.tools'`

- [ ] **Step 3: Write `f0_pa_actions_mcp/tools.py`** (gate helpers + run_test only; later tasks append)

```python
"""Gated write tools + reads for the ProjectAchilles actions server.

Flow for every gated tool: resolve (pre-gate) -> no token? return intent ->
token? gate.execute_async (flag + single-use token + audit) -> result finding.
Every failure is a finding, never an exception.
"""
from __future__ import annotations

from typing import Any

from f0_sectools_core.gating.actions import GatedAction, GateDenied
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from .client import ProjectAchillesError
from .errors import map_pa_error
from .resolve import ResolveFailed, resolve_agent, resolve_build, resolve_test

_SOURCE = "projectachilles"


def _intent(
    action_name: str,
    target: str,
    title: str,
    entity: Entity | None,
    evidence: list[Evidence],
) -> Finding:
    short = action_name.split(".")[-1]
    return Finding(
        source=_SOURCE,
        finding_type=FindingType.action,
        severity=Severity.high,
        title=f"Pending action: {title} (requires confirmation)",
        entity=entity,
        evidence=[*evidence, Evidence(key="confirmation_target", value=target)],
        recommended_action=RecommendedAction(
            summary=(
                f"To execute, an operator must run: python scripts/confirm_action.py "
                f'{short} "{target}" --platform projectachilles — then call this '
                f"tool again with the printed confirmation_token."
            ),
            gated_action=action_name,
            confidence="high",
        ),
    )


def _refusal(action_name: str, target: str, exc: GateDenied) -> Finding:
    return Finding(
        source=_SOURCE,
        finding_type=FindingType.action,
        severity=Severity.info,
        title=f"Action {action_name} not taken for {target}: {exc}",
        recommended_action=RecommendedAction(
            summary=(
                "Set PROJECTACHILLES_ALLOW_WRITE=true and supply a fresh token from "
                "scripts/confirm_action.py (--platform projectachilles), then retry."
            ),
            gated_action=action_name,
            confidence="high",
        ),
    )


def _after_gate_error(
    e: ProjectAchillesError, gate_name: str, target: str, capability: str
) -> list[Finding]:
    finding = map_pa_error(e, capability)
    if finding:
        return [finding]
    # Unmapped platform error after the token was consumed: degrade gracefully.
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action not applied: {capability} for {target} "
            f"(platform error {e.status})",
            evidence=[Evidence(key="error", value=e.message)],
            recommended_action=RecommendedAction(
                summary=(
                    f"ProjectAchilles rejected the {capability} request. The "
                    "confirmation token was consumed; retry with a fresh one."
                ),
                gated_action=gate_name,
                confidence="high",
            ),
        )
    ]


async def run_test(
    pa: Any,
    gate: GatedAction,
    test_id: str,
    hostname: str,
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Run a validation test on ONE agent now (gated write). No token -> intent."""
    try:
        test = await resolve_test(pa, test_id)
        binary = await resolve_build(pa, test["test_uuid"])
        agent = await resolve_agent(pa, hostname)
    except ResolveFailed as e:
        return [e.finding]
    target = f"{test['test_uuid']}@{agent['hostname']}"
    entity = Entity(kind=EntityKind.host, id=agent["agent_id"], name=agent["hostname"])
    evidence = [
        Evidence(key="test_name", value=test["test_name"]),
        Evidence(key="test_uuid", value=test["test_uuid"]),
        Evidence(key="hostname", value=agent["hostname"]),
        Evidence(key="binary_name", value=binary),
    ]
    if not confirmation_token:
        return [
            _intent(
                gate.name, target,
                f"run test '{test['test_name']}' on {agent['hostname']}",
                entity, evidence,
            )
        ]
    body = {
        "org_id": agent["org_id"],
        "agent_ids": [agent["agent_id"]],
        "test_uuid": test["test_uuid"],
        "test_name": test["test_name"],
        "binary_name": binary,
        "metadata": test["metadata"],
    }
    try:
        result = await gate.execute_async(
            target=target,
            actor=actor,
            token=confirmation_token,
            run=lambda: pa.post("/agent/admin/tasks", json=body),
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, "run test")
    task_ids = (result.get("data") or {}).get("task_ids") or []
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: run test '{test['test_name']}' "
            f"on {agent['hostname']}",
            entity=entity,
            evidence=[
                *evidence,
                *[Evidence(key="task_id", value=str(t)) for t in task_ids[:5]],
            ],
            recommended_action=RecommendedAction(
                summary="Track it with get_task_status; once completed, see the "
                "outcome with list_test_executions on the read server.",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_run_test.py -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy servers/projectachilles-actions-mcp/f0_pa_actions_mcp`
Expected: 6 PASS, clean

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py servers/projectachilles-actions-mcp/tests/test_run_test.py
git commit -m "feat(pa-actions): gated run_test with intent/refusal/audit flow"
```

---

### Task 5: schedule_test (flat args -> schedule_config union)

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (append)
- Test: `servers/projectachilles-actions-mcp/tests/test_schedule_test.py`

**Interfaces:**
- Consumes: Task 4 helpers (`_intent`, `_refusal`, `_after_gate_error`), Task 3 resolvers + `guidance`.
- Produces: `async schedule_test(pa, gate, test_id, hostname, schedule, run_time, run_date="", day="", day_of_month=0, confirmation_token="", actor="mcp-operator") -> list[Finding]`; module-private `_schedule_config(schedule, run_time, run_date, day, day_of_month) -> dict[str, Any]` (raises `ResolveFailed` on invalid combos).

- [ ] **Step 1: Write the failing test**

`servers/projectachilles-actions-mcp/tests/test_schedule_test.py`:

```python
"""schedule_test: flat-arg validation, config mapping, gate flow."""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore

from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.resolve import ResolveFailed
from f0_pa_actions_mcp.tools import _schedule_config, schedule_test

BASE = "https://org.agent.example.com"
UUID = "3f2a9c10-1111-4222-8333-444455556666"
TARGET = f"{UUID}@web-01"

TEST_RECORD = {
    "uuid": UUID, "name": "Brute Force SSH", "category": "credential-access",
    "subcategory": "brute-force", "severity": "high", "techniques": ["T1110"],
    "tactics": ["TA0006"], "threatActor": "APT29", "target": ["linux"],
    "complexity": "low", "tags": ["ssh"], "score": None, "integrations": [],
}
AGENTS = {"data": {"agents": [
    {"id": "ag-1", "org_id": "org-1", "hostname": "web-01", "status": "online"},
]}}
BUILD = {"data": {"exists": True, "filename": "brute_force_ssh"}}


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test", allow_write=True)


def _gate(tmp_path, enabled: bool = True) -> GatedAction:
    return GatedAction(
        "projectachilles.schedule_test",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "audit.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
    )


def _mock_reads(router) -> None:
    router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
        return_value=httpx.Response(200, json={"test": TEST_RECORD})
    )
    router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
        return_value=httpx.Response(200, json=BUILD)
    )
    router.get(f"{BASE}/api/agent/admin/agents").mock(
        return_value=httpx.Response(200, json=AGENTS)
    )


# ── _schedule_config mapping (pure function) ────────────────────────────────

def test_config_once():
    assert _schedule_config("once", "14:30", "2026-08-01", "", 0) == {
        "date": "2026-08-01", "time": "14:30"
    }


def test_config_daily():
    assert _schedule_config("daily", "02:30", "", "", 0) == {"time": "02:30"}


def test_config_weekly_sunday_is_zero():
    assert _schedule_config("weekly", "23:00", "", "sunday", 0) == {
        "days": [0], "time": "23:00"
    }


def test_config_weekly_monday_is_one():
    assert _schedule_config("weekly", "23:00", "", "monday", 0) == {
        "days": [1], "time": "23:00"
    }


def test_config_monthly():
    assert _schedule_config("monthly", "06:00", "", "", 15) == {
        "dayOfMonth": 15, "time": "06:00"
    }


@pytest.mark.parametrize(
    "args",
    [
        ("once", "14:30", "", "", 0),            # once without run_date
        ("once", "14:30", "08/01/2026", "", 0),  # bad date format
        ("weekly", "23:00", "", "", 0),          # weekly without day
        ("monthly", "06:00", "", "", 0),         # monthly without day_of_month
        ("monthly", "06:00", "", "", 32),        # day_of_month out of range
        ("daily", "2:30 AM", "", "", 0),         # bad time format
        ("daily", "25:00", "", "", 0),           # bad hour
        ("daily", "02:30", "2026-08-01", "", 0), # stray run_date for daily
        ("daily", "02:30", "", "monday", 0),     # stray day for daily
    ],
)
def test_config_invalid_combos_raise_guidance(args):
    with pytest.raises(ResolveFailed):
        _schedule_config(*args)


# ── gate flow ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_invalid_args_never_touch_network_or_gate(tmp_path):
    with respx.mock() as router:   # NO routes mocked: any call would error
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path), UUID, "web-01", "weekly", "23:00"
            )
    assert "day" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_no_token_returns_intent_with_schedule_description(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/schedules")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path), UUID, "web-01", "weekly", "23:00", day="sunday"
            )
    assert post.called is False
    f = findings[0]
    assert "Pending action" in f.title
    assert any(ev.key == "schedule" and "weekly" in ev.value for ev in f.evidence)
    assert TARGET in f.recommended_action.summary


@pytest.mark.asyncio
async def test_valid_token_posts_schedule_payload(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(201, json={"data": {
                "id": "sched-1", "status": "active",
                "next_run_at": "2026-07-19T23:00:00Z",
            }})
        )
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.schedule_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path), UUID, "web-01", "weekly", "23:00",
                day="sunday", confirmation_token=token,
            )
    assert post.call_count == 1
    body = json.loads(post.calls[0].request.content)
    assert body["schedule_type"] == "weekly"
    assert body["schedule_config"] == {"days": [0], "time": "23:00"}
    assert body["timezone"] == "UTC"
    assert body["org_id"] == "org-1"
    assert body["agent_ids"] == ["ag-1"]
    assert body["test_name"] == "Brute Force SSH"
    assert body["binary_name"] == "brute_force_ssh"
    assert "Action completed" in findings[0].title
    assert any(ev.value == "sched-1" for ev in findings[0].evidence)


@pytest.mark.asyncio
async def test_flag_off_refuses_schedule(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/schedules")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.schedule_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path, enabled=False), UUID, "web-01", "daily",
                "02:30", confirmation_token=token,
            )
    assert post.called is False
    assert "not taken" in findings[0].title
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_schedule_test.py -v`
Expected: FAIL — `ImportError: cannot import name '_schedule_config'`

- [ ] **Step 3: Append to `f0_pa_actions_mcp/tools.py`**

Add `import re` at the top of the file's import block, `guidance` to the `.resolve` import line, and append:

```python
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DOW = {
    "sunday": 0, "monday": 1, "tuesday": 2, "wednesday": 3,
    "thursday": 4, "friday": 5, "saturday": 6,
}


def _schedule_config(
    schedule: str, run_time: str, run_date: str, day: str, day_of_month: int
) -> dict[str, Any]:
    """Map flat scalar args onto the backend's schedule_config union member.

    Exactly one type-specific extra is allowed per schedule type; anything
    missing, malformed, or stray raises ResolveFailed (pre-gate, no token cost).
    """
    if not _TIME_RE.match(run_time):
        raise ResolveFailed(guidance(
            f"run_time '{run_time}' is not valid",
            "Use 24h HH:MM, e.g. 02:30 or 23:00 (UTC).",
        ))
    stray: list[str] = []
    if schedule != "once" and run_date:
        stray.append("run_date")
    if schedule != "weekly" and day:
        stray.append("day")
    if schedule != "monthly" and day_of_month:
        stray.append("day_of_month")
    if stray:
        raise ResolveFailed(guidance(
            f"Arguments {', '.join(stray)} do not apply to schedule='{schedule}'",
            "once needs run_date; weekly needs day; monthly needs day_of_month; "
            "daily needs neither.",
        ))
    if schedule == "once":
        if not _DATE_RE.match(run_date):
            raise ResolveFailed(guidance(
                "A one-off schedule needs run_date as YYYY-MM-DD",
                "Example: schedule='once', run_date='2026-08-01', run_time='14:30'.",
            ))
        return {"date": run_date, "time": run_time}
    if schedule == "daily":
        return {"time": run_time}
    if schedule == "weekly":
        if day not in _DOW:
            raise ResolveFailed(guidance(
                "A weekly schedule needs day (monday..sunday)",
                "Example: schedule='weekly', day='sunday', run_time='23:00'.",
            ))
        return {"days": [_DOW[day]], "time": run_time}
    if schedule == "monthly":
        if not 1 <= day_of_month <= 31:
            raise ResolveFailed(guidance(
                "A monthly schedule needs day_of_month between 1 and 31",
                "Example: schedule='monthly', day_of_month=15, run_time='06:00'.",
            ))
        return {"dayOfMonth": day_of_month, "time": run_time}
    raise ResolveFailed(guidance(
        f"Unknown schedule type '{schedule}'",
        "Use one of: once, daily, weekly, monthly.",
    ))


def _describe_schedule(
    schedule: str, run_time: str, run_date: str, day: str, day_of_month: int
) -> str:
    if schedule == "once":
        return f"once on {run_date} at {run_time} UTC"
    if schedule == "weekly":
        return f"weekly on {day} at {run_time} UTC"
    if schedule == "monthly":
        return f"monthly on day {day_of_month} at {run_time} UTC"
    return f"daily at {run_time} UTC"


async def schedule_test(
    pa: Any,
    gate: GatedAction,
    test_id: str,
    hostname: str,
    schedule: str,
    run_time: str,
    run_date: str = "",
    day: str = "",
    day_of_month: int = 0,
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Schedule a validation test on ONE agent (gated write). No token -> intent."""
    try:
        cfg = _schedule_config(schedule, run_time, run_date, day, day_of_month)
        test = await resolve_test(pa, test_id)
        binary = await resolve_build(pa, test["test_uuid"])
        agent = await resolve_agent(pa, hostname)
    except ResolveFailed as e:
        return [e.finding]
    target = f"{test['test_uuid']}@{agent['hostname']}"
    desc = _describe_schedule(schedule, run_time, run_date, day, day_of_month)
    entity = Entity(kind=EntityKind.host, id=agent["agent_id"], name=agent["hostname"])
    evidence = [
        Evidence(key="test_name", value=test["test_name"]),
        Evidence(key="test_uuid", value=test["test_uuid"]),
        Evidence(key="hostname", value=agent["hostname"]),
        Evidence(key="schedule", value=desc),
    ]
    if not confirmation_token:
        return [
            _intent(
                gate.name, target,
                f"schedule test '{test['test_name']}' on {agent['hostname']} ({desc})",
                entity, evidence,
            )
        ]
    body = {
        "org_id": agent["org_id"],
        "agent_ids": [agent["agent_id"]],
        "test_uuid": test["test_uuid"],
        "test_name": test["test_name"],
        "binary_name": binary,
        "metadata": test["metadata"],
        "schedule_type": schedule,
        "schedule_config": cfg,
        "timezone": "UTC",
        "name": f"{test['test_name']} @ {agent['hostname']}",
    }
    try:
        result = await gate.execute_async(
            target=target,
            actor=actor,
            token=confirmation_token,
            run=lambda: pa.post("/agent/admin/schedules", json=body),
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, "schedule test")
    sched = result.get("data") or {}
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: scheduled '{test['test_name']}' "
            f"on {agent['hostname']} ({desc})",
            entity=entity,
            evidence=[
                *evidence,
                Evidence(key="schedule_id", value=str(sched.get("id", ""))),
                Evidence(key="next_run_at", value=str(sched.get("next_run_at") or "?")),
            ],
            recommended_action=RecommendedAction(
                summary="Verify with list_schedules; pause/resume later with "
                "set_schedule_status.",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_schedule_test.py servers/projectachilles-actions-mcp/tests/test_run_test.py -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy servers/projectachilles-actions-mcp/f0_pa_actions_mcp`
Expected: all PASS, clean

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py servers/projectachilles-actions-mcp/tests/test_schedule_test.py
git commit -m "feat(pa-actions): gated schedule_test with flat-arg config mapping"
```

---

### Task 6: set_schedule_status + cancel_task

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (append)
- Test: `servers/projectachilles-actions-mcp/tests/test_schedule_status_and_cancel.py`

**Interfaces:**
- Consumes: Task 4 helpers.
- Produces: `async set_schedule_status(pa, gate, schedule_id, status, confirmation_token="", actor="mcp-operator") -> list[Finding]`; `async cancel_task(pa, gate, task_id, confirmation_token="", actor="mcp-operator") -> list[Finding]`.

- [ ] **Step 1: Write the failing test**

`servers/projectachilles-actions-mcp/tests/test_schedule_status_and_cancel.py`:

```python
"""set_schedule_status + cancel_task gate tests."""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore

from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.tools import cancel_task, set_schedule_status

BASE = "https://org.agent.example.com"


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test", allow_write=True)


def _gate(tmp_path, name: str, enabled: bool = True) -> GatedAction:
    return GatedAction(
        name,
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "audit.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
    )


@pytest.mark.asyncio
async def test_pause_no_token_returns_intent_no_call(tmp_path):
    with respx.mock() as router:
        patch = router.patch(f"{BASE}/api/agent/admin/schedules/sched-1")
        gate = _gate(tmp_path, "projectachilles.set_schedule_status")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await set_schedule_status(pa, gate, "sched-1", "paused")
    assert patch.called is False
    assert "Pending action" in findings[0].title
    assert "sched-1:paused" in findings[0].recommended_action.summary


@pytest.mark.asyncio
async def test_pause_token_bound_to_status_not_reusable_for_resume(tmp_path):
    with respx.mock() as router:
        patch = router.patch(f"{BASE}/api/agent/admin/schedules/sched-1")
        gate = _gate(tmp_path, "projectachilles.set_schedule_status")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.set_schedule_status", "sched-1:paused")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await set_schedule_status(pa, gate, "sched-1", "active", token)
    assert patch.called is False                 # pause token can't resume
    assert "not taken" in findings[0].title


@pytest.mark.asyncio
async def test_pause_valid_token_patches_status(tmp_path):
    with respx.mock() as router:
        patch = router.patch(f"{BASE}/api/agent/admin/schedules/sched-1").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "sched-1", "status": "paused", "next_run_at": None,
            }})
        )
        gate = _gate(tmp_path, "projectachilles.set_schedule_status")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.set_schedule_status", "sched-1:paused")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await set_schedule_status(pa, gate, "sched-1", "paused", token)
    assert patch.call_count == 1
    assert json.loads(patch.calls[0].request.content) == {"status": "paused"}
    assert "Action completed" in findings[0].title
    assert any(ev.key == "status" and ev.value == "paused" for ev in findings[0].evidence)


@pytest.mark.asyncio
async def test_empty_schedule_id_guides_without_gate(tmp_path):
    gate = _gate(tmp_path, "projectachilles.set_schedule_status")
    async with ProjectAchillesClient(_cfg()) as pa:
        findings = await set_schedule_status(pa, gate, "  ", "paused")
    assert "schedule_id" in findings[0].title


@pytest.mark.asyncio
async def test_cancel_no_token_returns_intent(tmp_path):
    with respx.mock() as router:
        post = router.post(f"{BASE}/api/agent/admin/tasks/task-1/cancel")
        gate = _gate(tmp_path, "projectachilles.cancel_task")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_task(pa, gate, "task-1")
    assert post.called is False
    assert "Pending action" in findings[0].title


@pytest.mark.asyncio
async def test_cancel_valid_token_posts_and_reports_status(tmp_path):
    with respx.mock() as router:
        post = router.post(f"{BASE}/api/agent/admin/tasks/task-1/cancel").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "task-1", "status": "expired",
            }})
        )
        gate = _gate(tmp_path, "projectachilles.cancel_task")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.cancel_task", "task-1")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_task(pa, gate, "task-1", token)
    assert post.call_count == 1
    assert "Action completed" in findings[0].title


@pytest.mark.asyncio
async def test_cancel_terminal_task_400_becomes_finding(tmp_path):
    with respx.mock() as router:
        router.post(f"{BASE}/api/agent/admin/tasks/task-1/cancel").mock(
            return_value=httpx.Response(400, json={"error": "task already terminal"})
        )
        gate = _gate(tmp_path, "projectachilles.cancel_task")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.cancel_task", "task-1")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_task(pa, gate, "task-1", token)
    assert len(findings) == 1
    assert "rejected" in findings[0].title.lower()
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_schedule_status_and_cancel.py -v`
Expected: FAIL — `ImportError: cannot import name 'set_schedule_status'`

- [ ] **Step 3: Append to `f0_pa_actions_mcp/tools.py`**

```python
async def set_schedule_status(
    pa: Any,
    gate: GatedAction,
    schedule_id: str,
    status: str,
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Pause or resume a schedule (gated write). No token -> intent."""
    sid = schedule_id.strip()
    if not sid:
        return [guidance(
            "schedule_id is required",
            "Find the id with list_schedules first.",
        )]
    if status not in ("active", "paused"):
        return [guidance(
            f"Unknown status '{status}'",
            "Use status='paused' to pause or status='active' to resume.",
        )]
    target = f"{sid}:{status}"
    verb = "pause" if status == "paused" else "resume"
    entity = Entity(kind=EntityKind.rule, id=sid)
    evidence = [Evidence(key="schedule_id", value=sid),
                Evidence(key="new_status", value=status)]
    if not confirmation_token:
        return [_intent(gate.name, target, f"{verb} schedule {sid}", entity, evidence)]
    try:
        result = await gate.execute_async(
            target=target,
            actor=actor,
            token=confirmation_token,
            run=lambda: pa.patch(f"/agent/admin/schedules/{sid}", json={"status": status}),
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, f"{verb} schedule")
    sched = result.get("data") or {}
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: {verb} schedule {sid}",
            entity=entity,
            evidence=[
                Evidence(key="status", value=str(sched.get("status", status))),
                Evidence(key="next_run_at", value=str(sched.get("next_run_at") or "—")),
            ],
            recommended_action=RecommendedAction(
                summary="Verify with list_schedules.",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]


async def cancel_task(
    pa: Any,
    gate: GatedAction,
    task_id: str,
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Cancel a pending/running test task (gated write). No token -> intent."""
    tid = task_id.strip()
    if not tid:
        return [guidance(
            "task_id is required",
            "The task_id comes from run_test's result or get_task_status.",
        )]
    target = tid
    entity = Entity(kind=EntityKind.rule, id=tid)
    evidence = [Evidence(key="task_id", value=tid)]
    if not confirmation_token:
        return [_intent(gate.name, target, f"cancel task {tid}", entity, evidence)]
    try:
        result = await gate.execute_async(
            target=target,
            actor=actor,
            token=confirmation_token,
            run=lambda: pa.post(f"/agent/admin/tasks/{tid}/cancel"),
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, "cancel task")
    task = result.get("data") or {}
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: cancel task {tid}",
            entity=entity,
            evidence=[Evidence(key="status", value=str(task.get("status", "expired")))],
            recommended_action=RecommendedAction(
                summary="Confirm with get_task_status.",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy servers/projectachilles-actions-mcp/f0_pa_actions_mcp`
Expected: all PASS, clean

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py servers/projectachilles-actions-mcp/tests/test_schedule_status_and_cancel.py
git commit -m "feat(pa-actions): gated set_schedule_status and cancel_task"
```

---

### Task 7: Read tools — list_schedules + get_task_status

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (append)
- Test: `servers/projectachilles-actions-mcp/tests/test_read_tools.py`

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces: `async list_schedules(pa, status: str = "") -> list[Finding]`; `async get_task_status(pa, task_id: str) -> list[Finding]`.

- [ ] **Step 1: Write the failing test**

`servers/projectachilles-actions-mcp/tests/test_read_tools.py`:

```python
"""Ungated reads: list_schedules and get_task_status."""
from __future__ import annotations

import httpx
import pytest
import respx
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.schema.findings import Severity

from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.tools import get_task_status, list_schedules

BASE = "https://org.agent.example.com"


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test")


SCHEDULES = {"data": [
    {"id": "sched-1", "name": "BF nightly", "test_name": "Brute Force SSH",
     "schedule_type": "daily", "status": "active",
     "next_run_at": "2026-07-19T02:30:00Z", "agent_ids": ["ag-1"]},
    {"id": "sched-2", "name": None, "test_name": "Ransomware Sim",
     "schedule_type": "weekly", "status": "paused",
     "next_run_at": None, "agent_ids": ["ag-1", "ag-2"]},
]}


@pytest.mark.asyncio
async def test_list_schedules_one_finding_per_schedule():
    with respx.mock() as router:
        route = router.get(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(200, json=SCHEDULES)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_schedules(pa)
    assert route.calls[0].request.url.params.get("status") is None
    assert len(findings) == 2
    assert "BF nightly" in findings[0].title
    assert any(ev.key == "next_run_at" for ev in findings[0].evidence)
    assert any(ev.key == "agent_count" and ev.value == "2" for ev in findings[1].evidence)


@pytest.mark.asyncio
async def test_list_schedules_status_filter_passed_through():
    with respx.mock() as router:
        route = router.get(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_schedules(pa, status="paused")
    assert route.calls[0].request.url.params["status"] == "paused"
    assert len(findings) == 1                     # honest empty summary finding
    assert "0" in findings[0].title


@pytest.mark.asyncio
async def test_get_task_status_completed_is_info():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-1").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "task-1", "status": "completed", "agent_id": "ag-1",
                "payload": {"test_name": "Brute Force SSH"},
            }})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-1")
    f = findings[0]
    assert f.severity == Severity.info
    assert "completed" in f.title
    assert any(ev.key == "test_name" and "Brute Force" in ev.value for ev in f.evidence)


@pytest.mark.asyncio
async def test_get_task_status_failed_is_medium():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-2").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "task-2", "status": "failed", "error": "timeout",
                "payload": {"test_name": "Ransomware Sim"},
            }})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-2")
    assert findings[0].severity == Severity.medium


@pytest.mark.asyncio
async def test_get_task_status_404_is_graceful():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/gone").mock(
            return_value=httpx.Response(404, json={"error": "Task not found"})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "gone")
    assert len(findings) == 1
    assert "404" in findings[0].title


@pytest.mark.asyncio
async def test_get_task_status_empty_id_guides():
    async with ProjectAchillesClient(_cfg()) as pa:
        findings = await get_task_status(pa, " ")
    assert "task_id" in findings[0].title
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_read_tools.py -v`
Expected: FAIL — `ImportError: cannot import name 'get_task_status'`

- [ ] **Step 3: Append to `f0_pa_actions_mcp/tools.py`**

```python
async def list_schedules(pa: Any, status: str = "") -> list[Finding]:
    """List recurring test schedules (read). status '' = all."""
    params: dict[str, Any] = {}
    if status:
        params["status"] = status
    try:
        resp = await pa.get("/agent/admin/schedules", params=params or None)
    except Exception as e:
        finding = map_pa_error(e, "list schedules")
        if finding:
            return [finding]
        raise
    rows = resp.get("data") if isinstance(resp, dict) else None
    rows = rows if isinstance(rows, list) else []
    if not rows:
        which = f"{status} " if status else ""
        return [
            Finding(
                source=_SOURCE,
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"0 {which}test schedules found",
                entity=Entity(kind=EntityKind.tenant, id="schedules"),
            )
        ]
    out: list[Finding] = []
    for s in rows[:50]:
        if not isinstance(s, dict):
            continue
        name = s.get("name") or s.get("test_name") or "schedule"
        out.append(
            Finding(
                source=_SOURCE,
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Schedule: {name} ({s.get('schedule_type', '?')}, "
                f"{s.get('status', '?')})",
                entity=Entity(kind=EntityKind.rule, id=str(s.get("id", "")),
                              name=str(name)),
                evidence=[
                    Evidence(key="test_name", value=str(s.get("test_name") or "?")),
                    Evidence(key="next_run_at", value=str(s.get("next_run_at") or "—")),
                    Evidence(key="agent_count",
                             value=str(len(s.get("agent_ids") or []))),
                ],
            )
        )
    return out


_TASK_DONE_BAD = ("failed", "expired")


async def get_task_status(pa: Any, task_id: str) -> list[Finding]:
    """Status of one test-run task by task_id (read)."""
    tid = task_id.strip()
    if not tid:
        return [guidance(
            "task_id is required",
            "The task_id comes from run_test's result finding.",
        )]
    try:
        resp = await pa.get(f"/agent/admin/tasks/{tid}")
    except Exception as e:
        finding = map_pa_error(e, "task status")
        if finding:
            return [finding]
        raise
    t = resp.get("data") if isinstance(resp, dict) else None
    t = t if isinstance(t, dict) else {}
    status = str(t.get("status", "unknown"))
    payload = t.get("payload") if isinstance(t.get("payload"), dict) else {}
    sev = Severity.medium if status in _TASK_DONE_BAD else Severity.info
    evidence = [
        Evidence(key="status", value=status),
        Evidence(key="test_name", value=str(payload.get("test_name") or "?")),
        Evidence(key="agent_id", value=str(t.get("agent_id") or "?")),
    ]
    if t.get("error"):
        evidence.append(Evidence(key="error", value=str(t["error"])))
    summary = (
        "See the outcome with list_test_executions on the ProjectAchilles read server."
        if status == "completed"
        else "Poll again later; cancel with cancel_task if it should not run."
    )
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.posture,
            severity=sev,
            title=f"Task {tid}: {status}",
            entity=Entity(kind=EntityKind.rule, id=tid),
            evidence=evidence,
            recommended_action=RecommendedAction(summary=summary, confidence="high"),
        )
    ]
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy servers/projectachilles-actions-mcp/f0_pa_actions_mcp`
Expected: all PASS, clean

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py servers/projectachilles-actions-mcp/tests/test_read_tools.py
git commit -m "feat(pa-actions): list_schedules and get_task_status reads"
```

---

### Task 8: server.py — FastMCP registration with Literal enums + redaction

**Files:**
- Create: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py`
- Test: `servers/projectachilles-actions-mcp/tests/test_server_registration.py`

**Interfaces:**
- Consumes: all tools from Tasks 4–7; `ProjectAchillesConfig`, gating classes, `redact_obj`.
- Produces: module attribute `mcp` (FastMCP, name `f0-pa-actions`) — the evals (Task 9) import `f0_pa_actions_mcp.server` and call `mcp.list_tools()`.

- [ ] **Step 1: Write the failing test**

`servers/projectachilles-actions-mcp/tests/test_server_registration.py`:

```python
"""Registration test: 6 tools, Literal enums surface in the schema."""
from __future__ import annotations

import pytest

from f0_pa_actions_mcp import server


@pytest.mark.asyncio
async def test_exactly_six_tools_registered():
    tools = await server.mcp.list_tools()
    assert {t.name for t in tools} == {
        "run_test", "schedule_test", "set_schedule_status",
        "cancel_task", "list_schedules", "get_task_status",
    }


@pytest.mark.asyncio
async def test_schedule_enum_is_closed_in_schema():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    props = tools["schedule_test"].inputSchema["properties"]
    assert set(props["schedule"]["enum"]) == {"once", "daily", "weekly", "monthly"}
    assert set(props["day"]["enum"]) == {
        "", "monday", "tuesday", "wednesday", "thursday", "friday",
        "saturday", "sunday",
    }


@pytest.mark.asyncio
async def test_status_enums_closed():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    set_props = tools["set_schedule_status"].inputSchema["properties"]
    assert set(set_props["status"]["enum"]) == {"active", "paused"}
    list_props = tools["list_schedules"].inputSchema["properties"]
    assert set(list_props["status"]["enum"]) == {"", "active", "paused", "completed"}
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_server_registration.py -v`
Expected: FAIL — `ImportError: cannot import name 'server'` (module missing)

- [ ] **Step 3: Write `f0_pa_actions_mcp/server.py`**

```python
"""ProjectAchilles actions MCP server (stdio). Gated writes + 2 reads.

Companion to the read-only projectachilles-mcp server. Every write is gated:
PROJECTACHILLES_ALLOW_WRITE=true AND a fresh single-use confirmation token
(scripts/confirm_action.py --platform projectachilles). Findings are redacted
before they leave the server.
"""
from __future__ import annotations

import os
from typing import Any, Literal

from dotenv import load_dotenv
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools
from .client import ProjectAchillesClient

load_dotenv(".env.projectachilles")

mcp = FastMCP("f0-pa-actions")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    """Dump findings and redact every payload before it leaves the server."""
    return [redact_obj(f.model_dump()) for f in findings]


def _gate(name: str, cfg: ProjectAchillesConfig) -> GatedAction:
    return GatedAction(
        name,
        enabled=cfg.allow_write,
        audit=AuditLog(os.environ.get("PROJECTACHILLES_AUDIT_LOG_PATH") or None),
        token_store=TokenStore(),
    )


_ACTOR = os.environ.get("PROJECTACHILLES_AUDIT_ACTOR", "mcp-operator")

_Day = Literal[
    "", "monday", "tuesday", "wednesday", "thursday", "friday",
    "saturday", "sunday",
]


@mcp.tool()
async def run_test(
    test_id: str, hostname: str, confirmation_token: str = ""
) -> list[dict[str, Any]]:
    """Run a ProjectAchilles validation test on ONE agent host now (GATED WRITE).

    test_id is the test's UUID (look it up with find_tests/get_test on the
    ProjectAchilles read server); hostname is the exact agent hostname. Call
    WITHOUT confirmation_token first: returns the intended action only. To
    execute, an operator runs scripts/confirm_action.py with the printed
    target and --platform projectachilles, then you call again with the token.
    Requires PROJECTACHILLES_ALLOW_WRITE=true and a read-write pa_ key.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.run_test(
                pa, _gate("projectachilles.run_test", cfg),
                test_id, hostname, confirmation_token, _ACTOR,
            )
        )


@mcp.tool()
async def schedule_test(
    test_id: str,
    hostname: str,
    schedule: Literal["once", "daily", "weekly", "monthly"],
    run_time: str,
    run_date: str = "",
    day: _Day = "",
    day_of_month: int = 0,
    confirmation_token: str = "",
) -> list[dict[str, Any]]:
    """Schedule a ProjectAchilles validation test on ONE agent host (GATED WRITE).

    run_time is 24h HH:MM in UTC. schedule=once also needs run_date
    (YYYY-MM-DD); weekly also needs day; monthly also needs day_of_month
    (1-31); daily needs neither. Same two-step confirmation flow as run_test.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.schedule_test(
                pa, _gate("projectachilles.schedule_test", cfg),
                test_id, hostname, schedule, run_time, run_date, day,
                day_of_month, confirmation_token, _ACTOR,
            )
        )


@mcp.tool()
async def set_schedule_status(
    schedule_id: str,
    status: Literal["active", "paused"],
    confirmation_token: str = "",
) -> list[dict[str, Any]]:
    """Pause (status=paused) or resume (status=active) a ProjectAchilles test
    schedule (GATED WRITE).

    Get schedule_id from list_schedules. Same two-step confirmation flow as
    run_test. Pausing is the supported way to stop a schedule (no delete).
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.set_schedule_status(
                pa, _gate("projectachilles.set_schedule_status", cfg),
                schedule_id, status, confirmation_token, _ACTOR,
            )
        )


@mcp.tool()
async def cancel_task(
    task_id: str, confirmation_token: str = ""
) -> list[dict[str, Any]]:
    """Cancel a pending/running ProjectAchilles test task (GATED WRITE).

    task_id comes from run_test's result or get_task_status. Same two-step
    confirmation flow as run_test.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.cancel_task(
                pa, _gate("projectachilles.cancel_task", cfg),
                task_id, confirmation_token, _ACTOR,
            )
        )


@mcp.tool()
async def list_schedules(
    status: Literal["", "active", "paused", "completed"] = "",
) -> list[dict[str, Any]]:
    """List ProjectAchilles recurring test schedules (read-only).

    Scheduled future runs — not past results (use list_test_executions on the
    read server for those). status '' = all.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(await tools.list_schedules(pa, status))


@mcp.tool()
async def get_task_status(task_id: str) -> list[dict[str, Any]]:
    """Check whether a ProjectAchilles test-run task finished (read-only).

    One task by task_id (from run_test). For the security outcome
    (blocked / not blocked), use list_test_executions on the read server
    after the task completes.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(await tools.get_task_status(pa, task_id))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy servers/projectachilles-actions-mcp/f0_pa_actions_mcp`
Expected: all PASS, clean. If the `day` enum assertion fails because FastMCP renders the Literal via `anyOf`/`const` instead of a flat `enum` list, adjust the TEST to read the schema the way FastMCP emits it (check `tools["schedule_test"].inputSchema` shape) — the requirement is that the schema advertises a CLOSED value set, not a free string; the tool code itself must not change.

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py servers/projectachilles-actions-mcp/tests/test_server_registration.py
git commit -m "feat(pa-actions): FastMCP server with Literal enums and redaction"
```

---

### Task 9: Evals — tasks.yaml + registry + combined-count bumps

**Files:**
- Create: `evals/projectachilles-actions/tasks.yaml`
- Modify: `evals/test_eval_coverage.py` (SERVERS list, around line 22)
- Modify: `evals/run.py` (SERVER_MODULES dict, around line 34)
- Modify: `evals/test_combined.py` (two count bumps)

**Interfaces:**
- Consumes: `f0_pa_actions_mcp.server` module (Task 8).
- Produces: eval coverage for all 6 tools; combined registry = 44 tools; per-server task total = 72.

- [ ] **Step 1: Write `evals/projectachilles-actions/tasks.yaml`**

```yaml
# Small-model tool-calling eval task set — ProjectAchilles ACTIONS server.
# See evals/defender/tasks.yaml for the field schema. evals/test_eval_coverage.py
# enforces that every tool has at least one task. These measure the gated-write
# two-step callability question (see the eval-findings memory: Gemma-12B gap).

- prompt: "Run the ProjectAchilles test 3f2a9c10-1111-4222-8333-444455556666 on host web-01 now."
  expect_tool: run_test

- prompt: "Execute validation test 8c1d2e30-2222-4333-9444-555566667777 against agent db-02."
  expect_tool: run_test

- prompt: "Schedule test 3f2a9c10-1111-4222-8333-444455556666 to run daily at 02:30 on host web-01."
  expect_tool: schedule_test
  expect_args: { schedule: daily, run_time: "02:30" }

- prompt: "Set up test 3f2a9c10-1111-4222-8333-444455556666 to run every sunday at 23:00 on web-01."
  expect_tool: schedule_test
  expect_args: { schedule: weekly, day: sunday }

- prompt: "Pause the ProjectAchilles schedule sched-42."
  expect_tool: set_schedule_status
  expect_args: { status: paused }

- prompt: "Resume schedule sched-42."
  expect_tool: set_schedule_status
  expect_args: { status: active }

- prompt: "Cancel the pending ProjectAchilles test task task-99."
  expect_tool: cancel_task

- prompt: "What recurring ProjectAchilles test schedules do we have?"
  expect_tool: list_schedules

- prompt: "Did ProjectAchilles task task-99 finish yet?"
  expect_tool: get_task_status
```

- [ ] **Step 2: Register the server in both eval registries**

In `evals/test_eval_coverage.py`, extend `SERVERS`:

```python
SERVERS = [
    ("defender", "f0_defender_mcp.server"),
    ("entra", "f0_entra_mcp.server"),
    ("limacharlie", "f0_limacharlie_mcp.server"),
    ("projectachilles", "f0_projectachilles_mcp.server"),
    ("intune", "f0_intune_mcp.server"),
    ("tenable", "f0_tenable_mcp.server"),
    ("projectachilles-actions", "f0_pa_actions_mcp.server"),
]
```

In `evals/run.py`, extend `SERVER_MODULES`:

```python
SERVER_MODULES = {
    "defender": "f0_defender_mcp.server",
    "entra": "f0_entra_mcp.server",
    "limacharlie": "f0_limacharlie_mcp.server",
    "projectachilles": "f0_projectachilles_mcp.server",
    "intune": "f0_intune_mcp.server",
    "tenable": "f0_tenable_mcp.server",
    "projectachilles-actions": "f0_pa_actions_mcp.server",
}
```

- [ ] **Step 3: Bump the hardcoded counts in `evals/test_combined.py`**

Rename/update the union test (38 → 44) and add a spot-check for the new server:

```python
async def test_combined_registry_unions_all_44_tools():
    tools = await combined_tool_schemas()
    names = [t["function"]["name"] for t in tools]
    assert len(names) == 44, f"expected 44 tools, got {len(names)}"
    assert len(set(names)) == 44, "tool names must be unique across servers"
    # spot-check one tool from each server is present
    for expected in (
        "isolate_host",
        "list_risky_users",
        "query_telemetry",
        "get_defense_score",
        "list_assets",
        "schedule_test",
    ):
        assert expected in names
```

Update the per-server count block (63 → 72):

```python
    # 15 defender + 8 entra + 10 limacharlie + 12 projectachilles + 8 intune
    # + 10 tenable + 9 projectachilles-actions = 72, plus probes.
```
and
```python
    assert len(per_server) == 72
```

- [ ] **Step 4: Run the full suite**

Run: `uv run pytest`
Expected: ALL PASS (the eval-coverage test now enforces ≥1 task per new tool; the combined counts match). If `test_combined` fails on the count, the failure message reports the actual number — reconcile the yaml task count (9) and tool count (6) before touching the assertions again.

- [ ] **Step 5: Lint the changed eval files + commit**

Run: `uv run ruff check evals`
Expected: clean

```bash
git add evals/projectachilles-actions/tasks.yaml evals/test_eval_coverage.py evals/run.py evals/test_combined.py
git commit -m "feat(evals): pa-actions task set and registry (44 tools, 72 tasks)"
```

---

### Task 10: Smoke script + skill + docs

**Files:**
- Create: `scripts/live_smoke_projectachilles_actions.py`
- Create: `skills/projectachilles/run-validation-test/SKILL.md`
- Modify: `skills/cross-platform/validation-coverage-loop/SKILL.md` (add one cross-ref line — read the file first, add under its Tools/Procedure section)
- Modify: `servers/projectachilles-mcp/.env.projectachilles.example` (ALLOW_WRITE block)
- Modify: `CLAUDE.md` (architecture tree, skills list, Platform Integrations row)
- Modify: `README.md` (status/server table — read it and mirror the existing per-server phrasing)
- Modify: `docs/user-guide/README.md` (support matrix — read it and mirror existing rows)

- [ ] **Step 1: Write `scripts/live_smoke_projectachilles_actions.py`**

```python
"""Live smoke test for the ProjectAchilles ACTIONS server against a real instance.

Usage (from the repo root):
    1. Ensure ./.env.projectachilles has PROJECTACHILLES_BASE_URL and a
       READ-WRITE-scope PROJECTACHILLES_API_KEY (pa_...). Writes additionally
       need PROJECTACHILLES_ALLOW_WRITE=true.
    2. uv run python scripts/live_smoke_projectachilles_actions.py
       # reads + INTENT-ONLY gated calls (no state change, no token needed)
    3. Full write pass (creates a real task!):
       uv run python scripts/live_smoke_projectachilles_actions.py \
           --execute --test-uuid <uuid> --hostname <host> --token <token>
       # token from: python scripts/confirm_action.py run_test \
       #   "<uuid>@<host>" --platform projectachilles

Prints REDACTED findings. Secrets are never printed.
"""
from __future__ import annotations

import argparse
import asyncio
import json

from dotenv import load_dotenv
from f0_pa_actions_mcp import tools
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore
from f0_sectools_core.redaction.redact import redact_obj

load_dotenv(".env.projectachilles")


def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:8]:
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 8:
        print(f"... ({len(findings) - 8} more)")


def _gate(name: str, cfg: ProjectAchillesConfig) -> GatedAction:
    return GatedAction(name, enabled=cfg.allow_write, audit=AuditLog(),
                       token_store=TokenStore())


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--execute", action="store_true",
                    help="run the FULL write pass (creates a real task)")
    ap.add_argument("--test-uuid", default="")
    ap.add_argument("--hostname", default="")
    ap.add_argument("--token", default="")
    args = ap.parse_args()

    cfg = ProjectAchillesConfig.from_env()
    print(f"Instance {cfg.base_url}  allow_write={cfg.allow_write}")
    async with ProjectAchillesClient(cfg) as pa:
        _show("list_schedules", await tools.list_schedules(pa))
        # Intent-only gated calls: no token -> no state change, verifies the
        # resolution chain (test lookup, build lookup, agent match) live.
        if args.test_uuid and args.hostname:
            _show(
                "run_test INTENT",
                await tools.run_test(
                    pa, _gate("projectachilles.run_test", cfg),
                    args.test_uuid, args.hostname,
                ),
            )
            _show(
                "schedule_test INTENT (daily 02:30)",
                await tools.schedule_test(
                    pa, _gate("projectachilles.schedule_test", cfg),
                    args.test_uuid, args.hostname, "daily", "02:30",
                ),
            )
        if args.execute:
            if not (args.test_uuid and args.hostname and args.token):
                print("--execute needs --test-uuid, --hostname and --token")
                return
            findings = await tools.run_test(
                pa, _gate("projectachilles.run_test", cfg),
                args.test_uuid, args.hostname, args.token,
            )
            _show("run_test EXECUTE", findings)
            task_ids = [
                ev.value for f in findings for ev in f.evidence
                if ev.key == "task_id"
            ]
            if task_ids:
                _show("get_task_status", await tools.get_task_status(pa, task_ids[0]))


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: Write `skills/projectachilles/run-validation-test/SKILL.md`**

(Description must be ≤60 chars — `Run or schedule a ProjectAchilles validation test (gated)` is 58.)

```markdown
---
name: run-validation-test
description: Run or schedule a ProjectAchilles validation test (gated)
version: 1.0.0
metadata:
  hermes:
    tags: [security, projectachilles, validation, gated-write, detection-engineer]
    category: security
---

# Run or Schedule a ProjectAchilles Validation Test

## When to Use

The user wants to actually EXECUTE a validation test — "run the brute-force
test on web-01", "schedule the ransomware sim nightly", "pause that
schedule", "cancel that run". Uses the **f0_sectools ProjectAchilles
ACTIONS** MCP server (gated writes). For finding tests, scores, or past
results, use the read server instead (find_tests, get_defense_score,
list_test_executions).

## Tools

Base tool names (runtime may prefix): `run_test`, `schedule_test`,
`set_schedule_status`, `cancel_task` (all GATED), `list_schedules`,
`get_task_status` (reads).

## Procedure

1. Resolve the test first: use `find_tests`/`get_test` (read server) to get
   the test's **uuid** — the actions server takes a uuid, not a name.
2. Call the gated tool WITHOUT `confirmation_token`. You get back the
   fully-resolved intent (test, host, agent id) and a `confirmation_target`
   evidence value.
3. STOP and hand the operator the exact command from the finding:
   `python scripts/confirm_action.py <action> "<target>" --platform
   projectachilles`. You cannot generate this token yourself.
4. Call the same tool again with the SAME arguments plus the operator's
   token. Tokens are single-use, expire in 15 minutes, and are bound to the
   exact action + target — changed arguments mean a fresh token.
5. Verify: `get_task_status` for runs (then `list_test_executions` on the
   read server for the blocked/not-blocked outcome); `list_schedules` for
   schedules.

## Pitfalls

- The test must be BUILT in the ProjectAchilles console first; an unbuilt
  test returns a "not built" finding, not an error.
- One host per call (exact hostname match). Fleet-wide runs are not
  supported here — use the PA console.
- All schedule times are UTC, 24h HH:MM.
- "Unschedule" = pause (`set_schedule_status` status=paused). There is no
  delete — that is admin-only in the platform.
- If every write returns a permission finding, the pa_ key is read-only —
  the operator must issue a read-write-scope key.

## Verification

The action finding says "Action completed"; follow its recommended action.
A "Pending action" finding means step 3 has not happened yet — that is the
expected first response, not a failure.
```

- [ ] **Step 3: Cross-ref from the coverage-loop skill**

Read `skills/cross-platform/validation-coverage-loop/SKILL.md`; in its
procedure where weak techniques lead to re-testing, add ONE line (adapted to
the surrounding format):

```markdown
To actually run or schedule the covering test from here, switch to the
run-validation-test skill (ProjectAchilles actions server, gated).
```

Run: `uv run pytest skills/test_skills_valid.py -v`
Expected: PASS (new SKILL.md frontmatter valid, description ≤60)

- [ ] **Step 4: Update `.env.projectachilles.example`**

Replace the final commented block:

```
# Read-only by default. No write actions are exposed (a read-scope key cannot
# write anyway). Reserved for future gated actions.
# PROJECTACHILLES_ALLOW_WRITE=false
```

with:

```
# Gated writes (the projectachilles-actions server: run/schedule/pause/cancel
# tests). Requires BOTH this flag AND a **read-write**-scope pa_ key (a
# read-only key 403s on every write). Each action also needs a fresh
# single-use confirmation token from scripts/confirm_action.py
# (--platform projectachilles). Leave false unless you use the actions server.
PROJECTACHILLES_ALLOW_WRITE=false

# Optional overrides for the gated-action audit trail.
# PROJECTACHILLES_AUDIT_LOG_PATH=audit-logs/actions.log
# PROJECTACHILLES_AUDIT_ACTOR=mcp-operator
```

- [ ] **Step 5: Update CLAUDE.md**

Three edits (keep surrounding text intact):
1. Architecture tree, after `projectachilles-mcp/`: add line
   `    projectachilles-actions-mcp/   # built (live-validation pending) — gated writes`
2. Skills list in "Skills (one portable set)": extend the projectachilles set to
   `projectachilles/{defense-posture-review,coverage-gap-analysis,validation-fleet-review,explore-test-catalog,run-validation-test}`
3. Platform Integrations table, ProjectAchilles row: change the gated-write
   column from `—` to `run/schedule/pause/cancel test (actions server)`, and
   append to the "Implemented & live-validated" paragraph: a sentence that
   `projectachilles-actions-mcp` is built (6 tools: 4 gated writes + 2 reads,
   second consumer of core/gating) with live validation pending a read-write
   key.

- [ ] **Step 6: Update README.md and docs/user-guide/README.md**

Read each file first and mirror its existing phrasing/format:
- README: add the actions server to the server list/status with "built —
  live-validation pending" wording matching how intune-mcp is listed.
- User guide: add a support-matrix row for `projectachilles-actions`
  (6 tools, gated writes, needs read-write pa_ key +
  PROJECTACHILLES_ALLOW_WRITE=true) and mention the run-validation-test
  skill where the other PA skills are listed.

- [ ] **Step 7: Full verification**

Run: `uv run pytest && uv run ruff check . && uv run mypy .`
Expected: ALL PASS / clean. Also verify no secrets staged: `git status --short` shows no `.env.projectachilles` (only the `.example`).

- [ ] **Step 8: Commit**

```bash
git add scripts/live_smoke_projectachilles_actions.py skills/projectachilles/run-validation-test/SKILL.md skills/cross-platform/validation-coverage-loop/SKILL.md servers/projectachilles-mcp/.env.projectachilles.example CLAUDE.md README.md docs/user-guide/README.md
git commit -m "docs(pa-actions): smoke script, run-validation-test skill, docs wiring"
```

---

## Plan Self-Review (done at write time)

- **Spec coverage:** architecture/scaffold (T1), client post/patch (T1), errors incl. write-scope 403 (T2), resolution incl. exists:false + ambiguity (T3), gating flow + token targets + negative space (T4–T6), schedule union mapping + UTC + dow (T5), reads + severity mapping (T7), Literal enums + redaction boundary + descriptions with cross-refs (T8), evals + count bumps 38→44 / 63→72 (T9), smoke intent-default/--execute + skill + docs + env example (T10). Spec §Milestone 8 (live validation) is user-gated — intentionally not a task.
- **Type consistency:** `run_test(pa, gate, test_id, hostname, confirmation_token, actor)` used identically in T4 tests, T8 server, T10 smoke; `ResolveFailed.finding` in T3/T4/T5; `guidance()` exported from resolve.py and used in T5–T7.
- **Known judgment point (T8 Step 4):** FastMCP's JSON-schema rendering of `Literal` may use `enum` or `anyOf`+`const` depending on SDK version — the registration test may need to match the actual shape; the REQUIREMENT (closed value set in the advertised schema) is fixed.
```
