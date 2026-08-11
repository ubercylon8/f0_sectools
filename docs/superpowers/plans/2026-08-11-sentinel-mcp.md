# sentinel-mcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `servers/sentinel-mcp/` — a read-only MCP server exposing 7 small-model-safe tools over Microsoft Sentinel's two API surfaces (Log Analytics KQL + the Sentinel management API), giving f0_sectools its first visibility into non-Microsoft infrastructure telemetry.

**Architecture:** A thin server over the shared `core/`, following the CONTRIBUTING 12-step recipe. One `SentinelClient` composes **two** `GraphClient` instances — different hosts, token audiences, and Azure roles for the logs half vs. the objects half. A `normalize.py` layer collapses three vendors' inconsistent action fields into one 4-value vocabulary, and a `Usage`-based capability probe lets every tool degrade to a `posture` finding on a workspace that lacks its table. **No `core/` changes** beyond adding a config dataclass.

**Tech Stack:** Python 3.11+, `mcp` (MCPServer), `httpx` (via core's `GraphClient`), `pydantic` (via core's `Finding`), `pytest` + `pytest-asyncio`, `ruff`, `mypy --strict`, `uv` workspace.

**Spec:** `docs/superpowers/specs/2026-08-11-sentinel-mcp-design.md` (commit `fa82622`)

## Global Constraints

- **Read-only.** No tool mutates Sentinel state. No `core/gating/` usage in this server.
- **Every failure is a finding, never an exception.** Auth → `posture`; 403 → `Finding.permission_missing`; 429 → `Finding.rate_limited`; 502/503/504 → `Finding.api_unavailable`; KQL semantic error → `posture` carrying the sanitized reason.
- **Redact at the boundary.** `server.py` returns `redact_obj(f.model_dump())` for every finding, success and error paths alike.
- **Flat scalar arguments only.** No nested objects, no arrays-of-objects as inputs. Enums are the closed sets listed below and nowhere else.
- **Enums (verified against live data 2026-08-11):**
  - `action`: `allowed | blocked | detected | any`
  - `surface`: `dns | web | vpn`
  - `workload`: `sharepoint | onedrive | exchange | teams | any`
  - `severity_min`: `informational | low | medium | high`
  - `status`: `new | active | closed | any`
- **Bounding is mandatory.** `TimeGenerated` predicate emitted first in every generated query; `hours` clamped to `retention_days × 24` (default `720`); `limit` through `core.paging.clamp_limit`; no `indicator` → aggregate-only, never raw rows.
- **KQL injection defense.** Every caller-supplied value spliced into KQL passes a strict regex (`_IP_RE`, `_PORT_RE`, `_DOMAIN_RE`, `_WORD_RE`, `_UPN_RE`). A rejected value returns a `posture` finding naming the accepted form — never a silently dropped filter.
- **Header-row hygiene.** The tenant's Umbrella connectors ingest CSV headers as data (`Action_s == "Action"`, `Verdict_s == "Action"`, `AMP_Disposition_s == "AMP Disposition"`). Every Umbrella query and aggregate filters them out.
- **`source="sentinel"`** on every `Finding`.
- **Package name** `f0_sentinel_mcp`; **distribution** `f0-sentinel-mcp`; **MCP server name** `f0-sentinel`; **entry point** `f0-sentinel-mcp = "f0_sentinel_mcp.server:main"`.
- **Typecheck with `uv run mypy .` from the repo root, never scoped to one server.** Scoping mypy to a single server package makes `core` un-analyzable (it ships no `py.typed` marker), producing spurious `import-untyped` errors and the `no-any-return` errors that cascade from them. Verified 2026-08-11: the shipped `tenable-mcp` reproduces the same errors when scoped. Root `mypy .` is the CI gate.
- **Commit conventionally, never push.** Use `git commit -F <file>` when the message contains backticks.
- **`uv run python scripts/gen_docs.py` after any tool/docstring/skill change**, and commit the regenerated `docs/reference/` — CI's drift guard fails on stale docs.

---

## File Structure

**Create:**

| File | Responsibility |
|---|---|
| `servers/sentinel-mcp/pyproject.toml` | workspace member, deps, entry point |
| `servers/sentinel-mcp/README.md` | operator docs (follows `servers/_TEMPLATE.md`) |
| `servers/sentinel-mcp/.env.sentinel.example` | exact vars + required Azure roles |
| `servers/sentinel-mcp/f0_sentinel_mcp/__init__.py` | empty package marker |
| `servers/sentinel-mcp/f0_sentinel_mcp/client.py` | `SentinelClient` — the two-half client, row→dict conversion |
| `servers/sentinel-mcp/f0_sentinel_mcp/errors.py` | `map_sentinel_error` |
| `servers/sentinel-mcp/f0_sentinel_mcp/normalize.py` | action vocabulary, table registry, hygiene, bounds, KQL-safe regexes |
| `servers/sentinel-mcp/f0_sentinel_mcp/probe.py` | `Usage`-based capability probe + cache |
| `servers/sentinel-mcp/f0_sentinel_mcp/tools.py` | the 7 tools → `list[Finding]` |
| `servers/sentinel-mcp/f0_sentinel_mcp/server.py` | MCPServer registration + redaction boundary |
| `servers/sentinel-mcp/tests/conftest.py` | `FakeClient`, probe-cache reset fixture |
| `servers/sentinel-mcp/tests/test_tools.py` | contract tests |
| `evals/sentinel/tasks.yaml` | ≥1 task per tool + routing tasks |
| `scripts/live_smoke_sentinel.py` | recipe step 9 |
| `skills/sentinel/data-source-coverage/SKILL.md` | posture skill (default focus) |
| `skills/sentinel/network-investigation/SKILL.md` | firewall + DNS/web hunting |
| `skills/sentinel/detection-coverage/SKILL.md` | analytics-rule inventory |

**Modify:** `core/f0_sectools_core/auth/config.py`, `core/tests/test_config.py`, `evals/test_eval_coverage.py`, `evals/run.py`, `servers/defender-mcp/f0_defender_mcp/server.py` (docstrings only), `servers/purview-mcp/f0_purview_mcp/server.py` (docstrings only), `CLAUDE.md`, `README.md`, `docs/user-guide/README.md`, `integrations/pi/mcp.json`, `integrations/hermes/config.example.yaml`, `integrations/hermes/distribution/config.yaml`, `opencode.json`, `.opencode/skills/`.

---

### Task 1: `SentinelConfig` in core

**Files:**
- Modify: `core/f0_sectools_core/auth/config.py`
- Test: `core/tests/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `SentinelConfig` dataclass with fields `tenant_id: str`, `client_id: str`, `client_secret: str`, `workspace_id: str`, `subscription_id: str | None`, `resource_group: str | None`, `workspace_name: str | None`, `retention_days: int`, `verify_tls: bool`; property `has_arm: bool`; classmethod `from_env(prefix: str = "SENTINEL", env: Mapping[str, str] | None = None) -> SentinelConfig`.

- [ ] **Step 1: Write the failing tests**

Append to `core/tests/test_config.py`:

```python
def test_sentinel_config_from_env_minimal():
    cfg = SentinelConfig.from_env(
        env={
            "SENTINEL_TENANT_ID": "t",
            "SENTINEL_CLIENT_ID": "c",
            "SENTINEL_CLIENT_SECRET": "s",
            "SENTINEL_WORKSPACE_ID": "ws-guid",
        }
    )
    assert cfg.workspace_id == "ws-guid"
    assert cfg.retention_days == 30
    assert cfg.has_arm is False


def test_sentinel_config_has_arm_requires_all_three():
    base = {
        "SENTINEL_TENANT_ID": "t",
        "SENTINEL_CLIENT_ID": "c",
        "SENTINEL_CLIENT_SECRET": "s",
        "SENTINEL_WORKSPACE_ID": "w",
    }
    partial = SentinelConfig.from_env(env={**base, "SENTINEL_SUBSCRIPTION_ID": "sub"})
    assert partial.has_arm is False
    full = SentinelConfig.from_env(
        env={
            **base,
            "SENTINEL_SUBSCRIPTION_ID": "sub",
            "SENTINEL_RESOURCE_GROUP": "rg",
            "SENTINEL_WORKSPACE_NAME": "name",
        }
    )
    assert full.has_arm is True


def test_sentinel_config_retention_days_override_and_bad_value():
    base = {
        "SENTINEL_TENANT_ID": "t",
        "SENTINEL_CLIENT_ID": "c",
        "SENTINEL_CLIENT_SECRET": "s",
        "SENTINEL_WORKSPACE_ID": "w",
    }
    assert SentinelConfig.from_env(env={**base, "SENTINEL_RETENTION_DAYS": "90"}).retention_days == 90
    # A non-numeric value falls back to the default rather than raising: a bad
    # env value must not take the whole server down.
    assert SentinelConfig.from_env(env={**base, "SENTINEL_RETENTION_DAYS": "ninety"}).retention_days == 30


def test_sentinel_config_missing_workspace_id_raises():
    with pytest.raises(ValueError, match="SENTINEL_WORKSPACE_ID"):
        SentinelConfig.from_env(
            env={"SENTINEL_TENANT_ID": "t", "SENTINEL_CLIENT_ID": "c", "SENTINEL_CLIENT_SECRET": "s"}
        )
```

Add `SentinelConfig` to the existing import at the top of that test file.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest core/tests/test_config.py -k sentinel -v`
Expected: FAIL with `ImportError: cannot import name 'SentinelConfig'`

- [ ] **Step 3: Implement**

Append to `core/f0_sectools_core/auth/config.py`:

```python
@dataclass
class SentinelConfig:
    """Microsoft Sentinel credentials: an Entra app plus workspace coordinates.

    Two API surfaces with different RBAC. The logs half (KQL) needs only
    ``workspace_id`` and the Log Analytics Reader role. The objects half
    (analytics rules, watchlists) needs the ARM triple and Microsoft Sentinel
    Reader; when it is absent the server degrades gracefully rather than
    failing, so a logs-only deployment is a supported configuration.

    Loaded from .env.sentinel. Secrets never leave this layer or get logged.
    """

    tenant_id: str
    client_id: str
    client_secret: str
    workspace_id: str
    subscription_id: str | None = None
    resource_group: str | None = None
    workspace_name: str | None = None
    retention_days: int = 30
    verify_tls: bool = True

    @property
    def has_arm(self) -> bool:
        """True when all three ARM coordinates are present."""
        return bool(self.subscription_id and self.resource_group and self.workspace_name)

    @classmethod
    def from_env(
        cls, prefix: str = "SENTINEL", env: Mapping[str, str] | None = None
    ) -> SentinelConfig:
        env = env if env is not None else os.environ
        required = {
            k: f"{prefix}_{k.upper()}"
            for k in ("tenant_id", "client_id", "client_secret", "workspace_id")
        }
        missing = [name for name in required.values() if not env.get(name)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
        try:
            retention = int(env.get(f"{prefix}_RETENTION_DAYS", "30"))
        except ValueError:
            retention = 30
        if retention < 1:
            retention = 30
        return cls(
            tenant_id=env[required["tenant_id"]],
            client_id=env[required["client_id"]],
            client_secret=env[required["client_secret"]],
            workspace_id=env[required["workspace_id"]],
            subscription_id=env.get(f"{prefix}_SUBSCRIPTION_ID") or None,
            resource_group=env.get(f"{prefix}_RESOURCE_GROUP") or None,
            workspace_name=env.get(f"{prefix}_WORKSPACE_NAME") or None,
            retention_days=retention,
            verify_tls=env.get(f"{prefix}_VERIFY_TLS", "true").strip().lower() in _TRUE,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest core/tests/test_config.py -v && uv run mypy core`
Expected: PASS, mypy clean

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/auth/config.py core/tests/test_config.py
git commit -m "feat(sentinel): add SentinelConfig with optional ARM coordinates"
```

---

### Task 2: Scaffold the package and build `SentinelClient`

**Files:**
- Create: `servers/sentinel-mcp/pyproject.toml`, `servers/sentinel-mcp/.env.sentinel.example`, `servers/sentinel-mcp/f0_sentinel_mcp/__init__.py`, `servers/sentinel-mcp/f0_sentinel_mcp/client.py`, `servers/sentinel-mcp/tests/test_client.py`
- Test: `servers/sentinel-mcp/tests/test_client.py`

**Interfaces:**
- Consumes: `SentinelConfig` (Task 1); `GraphClient`, `GraphError` from `f0_sectools_core.auth.graph`.
- Produces:
  - `rows_to_dicts(body: dict[str, Any]) -> list[dict[str, Any]]`
  - `SentinelClient(config: SentinelConfig)` — async context manager with
    - `retention_days: int` (attribute)
    - `has_arm: bool` (attribute)
    - `async query(kql: str, timespan: str) -> list[dict[str, Any]]`
    - `async arm_list(resource: str) -> list[dict[str, Any]]`

- [ ] **Step 1: Create the scaffold files**

`servers/sentinel-mcp/pyproject.toml`:

```toml
[project]
name = "f0-sentinel-mcp"
version = "0.0.1"
description = "f0_sectools MCP server for Microsoft Sentinel (read-only) — KQL telemetry, incidents, detection coverage."
readme = "README.md"
requires-python = ">=3.11"
license = { text = "Apache-2.0" }
authors = [{ name = "F0RT1KA Contributors" }]
dependencies = [
    "f0-sectools-core",
    "mcp>=1.0",
    "python-dotenv>=1.0",
    "httpx>=0.27",
]

[project.scripts]
f0-sentinel-mcp = "f0_sentinel_mcp.server:main"

[tool.uv.sources]
f0-sectools-core = { workspace = true }

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["f0_sentinel_mcp"]
```

`servers/sentinel-mcp/.env.sentinel.example`:

```bash
# Microsoft Sentinel — read-only. Copy to ./.env.sentinel at the repo root.
#
# Azure roles required on the Log Analytics workspace resource:
#   * Log Analytics Reader        -> the KQL half (all telemetry tools)
#   * Microsoft Sentinel Reader   -> the objects half (get_detection_coverage)
# The two fail independently: without Sentinel Reader every other tool still works.

SENTINEL_TENANT_ID=
SENTINEL_CLIENT_ID=
SENTINEL_CLIENT_SECRET=

# Workspace GUID (Log Analytics workspace -> Overview -> Workspace ID).
SENTINEL_WORKSPACE_ID=

# Optional: ARM coordinates for get_detection_coverage. Omit them and that one
# tool returns a posture finding explaining what is missing; nothing else breaks.
SENTINEL_SUBSCRIPTION_ID=
SENTINEL_RESOURCE_GROUP=
SENTINEL_WORKSPACE_NAME=

# Optional: workspace retention in days (default 30). Caps every `hours`
# argument, so a query can never silently reach past retention and report
# "no activity" when it means "no data retained".
SENTINEL_RETENTION_DAYS=30
```

`servers/sentinel-mcp/f0_sentinel_mcp/__init__.py`: empty file.

**Do NOT create `servers/sentinel-mcp/tests/__init__.py`.** 7 of the 9 existing
servers ship no such file; only `purview-mcp` does, and it is the outlier.
Adding one makes the directory a package named `tests`, which collides with
purview's identically-named package and makes pytest refuse to register the
second `conftest.py` — breaking `uv run pytest` (the CI command) at collection.

- [ ] **Step 2: Sync the workspace**

Run: `uv sync --all-packages`
Expected: `f0-sentinel-mcp` appears as an installed workspace member.

- [ ] **Step 3: Write the failing tests**

`servers/sentinel-mcp/tests/test_client.py`:

```python
"""Contract tests for the Sentinel two-half client."""
from __future__ import annotations

import pytest
from f0_sectools_core.auth.config import SentinelConfig
from f0_sentinel_mcp.client import SentinelClient, rows_to_dicts


def _cfg(**over):
    base = dict(
        tenant_id="t", client_id="c", client_secret="s", workspace_id="ws",
        subscription_id="sub", resource_group="rg", workspace_name="name",
    )
    base.update(over)
    return SentinelConfig(**base)


def test_rows_to_dicts_maps_columns_onto_rows():
    body = {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [{"name": "DataType"}, {"name": "GB"}],
                "rows": [["CommonSecurityLog", 250.45], ["Syslog", 2.35]],
            }
        ]
    }
    assert rows_to_dicts(body) == [
        {"DataType": "CommonSecurityLog", "GB": 250.45},
        {"DataType": "Syslog", "GB": 2.35},
    ]


def test_rows_to_dicts_handles_empty_and_malformed():
    assert rows_to_dicts({}) == []
    assert rows_to_dicts({"tables": []}) == []
    assert rows_to_dicts({"tables": [{"columns": [], "rows": []}]}) == []


async def test_query_posts_body_and_returns_dicts(monkeypatch):
    captured = {}

    async def fake_post(path, json_body):
        captured["path"] = path
        captured["body"] = json_body
        return {"tables": [{"columns": [{"name": "n"}], "rows": [[1]]}]}

    client = SentinelClient(_cfg())
    monkeypatch.setattr(client._logs, "post", fake_post)
    rows = await client.query("Usage | take 1", "P30D")

    assert rows == [{"n": 1}]
    assert captured["path"] == "/workspaces/ws/query"
    assert captured["body"] == {"query": "Usage | take 1", "timespan": "P30D"}


async def test_arm_list_builds_securityinsights_path(monkeypatch):
    captured = {}

    async def fake_get(path, params=None):
        captured["path"] = path
        captured["params"] = params
        return {"value": [{"name": "rule-1"}]}

    client = SentinelClient(_cfg())
    monkeypatch.setattr(client._arm, "get", fake_get)
    out = await client.arm_list("alertRules")

    assert out == [{"name": "rule-1"}]
    assert captured["path"] == (
        "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights"
        "/workspaces/name/providers/Microsoft.SecurityInsights/alertRules"
    )
    assert captured["params"] == {"api-version": "2024-09-01"}


async def test_arm_list_without_arm_config_raises_valueerror():
    client = SentinelClient(_cfg(subscription_id=None))
    assert client.has_arm is False
    with pytest.raises(ValueError, match="ARM coordinates"):
        await client.arm_list("alertRules")


def test_client_exposes_retention_days():
    assert SentinelClient(_cfg()).retention_days == 30
    assert SentinelClient(_cfg(retention_days=90)).retention_days == 90


async def test_query_converts_transport_timeout_to_graph_error_504(monkeypatch):
    # A runaway scan over a very large table blows httpx's timeout rather than
    # returning HTTP 504. If that escapes as httpx.TimeoutException, every tool
    # re-raises and the "never raise" rule breaks exactly when it matters most.
    # Converting it here means errors.py's existing 504 branch handles it.
    async def fake_post(path, json_body):
        raise httpx.ReadTimeout("timed out")

    client = SentinelClient(_cfg())
    monkeypatch.setattr(client._logs, "post", fake_post)
    with pytest.raises(GraphError) as exc:
        await client.query("CommonSecurityLog | take 1", "PT24H")
    assert exc.value.status == 504


async def test_arm_list_converts_transport_timeout_too(monkeypatch):
    async def fake_get(path, params=None):
        raise httpx.ConnectTimeout("timed out")

    client = SentinelClient(_cfg())
    monkeypatch.setattr(client._arm, "get", fake_get)
    with pytest.raises(GraphError) as exc:
        await client.arm_list("alertRules")
    assert exc.value.status == 504
```

Add `import httpx` and `from f0_sectools_core.auth.graph import GraphError` to this test file's imports.

- [ ] **Step 4: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'f0_sentinel_mcp.client'`

- [ ] **Step 5: Implement the client**

`servers/sentinel-mcp/f0_sentinel_mcp/client.py`:

```python
"""Thin async client for Microsoft Sentinel's two API surfaces.

Sentinel is two APIs, not one, and they differ in host, token audience, and
Azure RBAC:

  * logs    -> https://api.loganalytics.azure.com/v1  (Log Analytics Reader)
  * objects -> https://management.azure.com           (Microsoft Sentinel Reader)

Both are plain OAuth2 client-credentials, so both are driven by core's
``GraphClient`` with a different ``base_url``/``scope`` — no core change was
needed. The two halves fail independently: a tenant may grant one role and not
the other, and the tools report that per-half rather than as a dead server.
"""
from __future__ import annotations

from typing import Any

import httpx
from f0_sectools_core.auth.config import PlatformConfig, SentinelConfig
from f0_sectools_core.auth.graph import GraphClient, GraphError

LOGS_BASE = "https://api.loganalytics.azure.com/v1"
LOGS_SCOPE = "https://api.loganalytics.io/.default"
ARM_BASE = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
ARM_API_VERSION = "2024-09-01"


def rows_to_dicts(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a Log Analytics ``{tables:[{columns,rows}]}`` payload to dicts.

    The query API returns columns and rows separately; every tool wants dicts.
    Defensive throughout — a malformed or empty payload yields an empty list
    rather than raising, because a query that matched nothing and a query that
    returned an odd shape are both "no findings", not "crash the agent".
    """
    tables = body.get("tables") or []
    if not tables:
        return []
    first = tables[0] or {}
    cols = [str(c.get("name", "")) for c in (first.get("columns") or [])]
    if not cols:
        return []
    return [dict(zip(cols, row)) for row in (first.get("rows") or [])]


class SentinelClient:
    def __init__(self, config: SentinelConfig) -> None:
        self._cfg = config
        platform = PlatformConfig(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret,
            verify_tls=config.verify_tls,
        )
        self._logs = GraphClient(platform, base_url=LOGS_BASE, scope=LOGS_SCOPE)
        self._arm = GraphClient(platform, base_url=ARM_BASE, scope=ARM_SCOPE)

    @property
    def retention_days(self) -> int:
        return self._cfg.retention_days

    @property
    def has_arm(self) -> bool:
        return self._cfg.has_arm

    @property
    def workspace_id(self) -> str:
        return self._cfg.workspace_id

    async def __aenter__(self) -> SentinelClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._logs.__aexit__()
        await self._arm.__aexit__()

    async def query(self, kql: str, timespan: str) -> list[dict[str, Any]]:
        """Run a KQL query against the workspace and return rows as dicts."""
        try:
            body = await self._logs.post(
                f"/workspaces/{self._cfg.workspace_id}/query",
                {"query": kql, "timespan": timespan},
            )
        except httpx.TimeoutException as e:
            # A scan too large to finish inside the transport timeout is
            # operationally a gateway timeout. Normalizing it here keeps the
            # "every failure is a finding" rule intact without teaching seven
            # tools about transport exceptions.
            raise GraphError(504, "query exceeded the request timeout") from e
        return rows_to_dicts(body)

    async def arm_list(self, resource: str) -> list[dict[str, Any]]:
        """List a Microsoft.SecurityInsights child resource (e.g. ``alertRules``)."""
        if not self._cfg.has_arm:
            raise ValueError(
                "ARM coordinates not configured (SENTINEL_SUBSCRIPTION_ID, "
                "SENTINEL_RESOURCE_GROUP, SENTINEL_WORKSPACE_NAME)"
            )
        path = (
            f"/subscriptions/{self._cfg.subscription_id}"
            f"/resourceGroups/{self._cfg.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self._cfg.workspace_name}"
            f"/providers/Microsoft.SecurityInsights/{resource}"
        )
        try:
            body = await self._arm.get(path, params={"api-version": ARM_API_VERSION})
        except httpx.TimeoutException as e:
            raise GraphError(504, "request exceeded the request timeout") from e
        value = body.get("value")
        return list(value) if isinstance(value, list) else []
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/tests/test_client.py -v && uv run mypy .`
Expected: PASS, mypy clean

> If `GraphClient.__aexit__` requires positional args, call `await self._logs.__aexit__(None, None, None)`. Confirm against `core/f0_sectools_core/auth/graph.py:47`.

- [ ] **Step 7: Commit**

```bash
git add servers/sentinel-mcp/
git commit -m "feat(sentinel): scaffold server package and two-half SentinelClient"
```

---

### Task 3: `errors.py` — every failure becomes a finding

**Files:**
- Create: `servers/sentinel-mcp/f0_sentinel_mcp/errors.py`
- Test: `servers/sentinel-mcp/tests/test_errors.py`

**Interfaces:**
- Consumes: `GraphError` from `f0_sectools_core.auth.graph`.
- Produces: `map_sentinel_error(e: Exception, capability: str, half: str = "logs") -> Finding | None` where `half` is `"logs"` or `"arm"`.

- [ ] **Step 1: Write the failing tests**

`servers/sentinel-mcp/tests/test_errors.py`:

```python
"""Contract tests for Sentinel error mapping."""
from __future__ import annotations

from f0_sectools_core.auth.graph import GraphError
from f0_sentinel_mcp.errors import map_sentinel_error


def test_401_returns_posture_not_exception():
    f = map_sentinel_error(GraphError(401, "unauthorized"), "Sentinel firewall telemetry")
    assert f is not None
    assert f.finding_type.value == "posture"
    assert "Sentinel firewall telemetry" in f.title


def test_403_logs_half_names_log_analytics_reader():
    f = map_sentinel_error(GraphError(403, "forbidden"), "firewall telemetry", half="logs")
    assert f is not None
    assert "Log Analytics Reader" in (f.recommended_action.summary if f.recommended_action else "")


def test_403_arm_half_names_sentinel_reader():
    # The two halves fail independently; telling the operator to grant the wrong
    # role is worse than saying nothing.
    f = map_sentinel_error(GraphError(403, "forbidden"), "detection coverage", half="arm")
    assert f is not None
    assert "Microsoft Sentinel Reader" in (
        f.recommended_action.summary if f.recommended_action else ""
    )


def test_429_rate_limited():
    f = map_sentinel_error(GraphError(429, "throttled"), "Sentinel incidents")
    assert f is not None and "Rate limited" in f.title


def test_503_api_unavailable():
    f = map_sentinel_error(GraphError(503, "bad gateway"), "Sentinel incidents")
    assert f is not None and "unavailable" in f.title.lower()


def test_400_semantic_error_carries_reason_so_model_can_self_correct():
    f = map_sentinel_error(
        GraphError(400, "SemanticError: 'summarize' operator: Failed to resolve 'ObservableType'"),
        "Sentinel KQL query",
    )
    assert f is not None
    assert f.finding_type.value == "posture"
    assert "ObservableType" in f.title or "ObservableType" in (
        f.recommended_action.summary if f.recommended_action else ""
    )


def test_504_timeout_suggests_narrowing():
    f = map_sentinel_error(GraphError(504, "gateway timeout"), "Sentinel firewall telemetry")
    assert f is not None
    assert f.finding_type.value == "posture"


def test_non_graph_error_returns_none_so_caller_reraises():
    assert map_sentinel_error(ValueError("nope"), "x") is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_errors.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'f0_sentinel_mcp.errors'`

- [ ] **Step 3: Implement**

`servers/sentinel-mcp/f0_sentinel_mcp/errors.py`:

```python
"""Map Sentinel API errors to graceful findings (Critical Rule: never raise)."""
from __future__ import annotations

from f0_sectools_core.auth.graph import GraphError
from f0_sectools_core.schema.findings import (
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

_ROLE = {
    "logs": "Log Analytics Reader",
    "arm": "Microsoft Sentinel Reader",
}


def map_sentinel_error(e: Exception, capability: str, half: str = "logs") -> Finding | None:
    """Return a graceful finding for known Sentinel errors, else None (caller re-raises).

    ``half`` selects which Azure role the operator is told to grant. The logs
    (KQL) and objects (ARM) halves are authorized independently, so naming the
    wrong role sends the operator to the wrong blade.
    """
    if not isinstance(e, GraphError):
        return None
    role = _ROLE.get(half, _ROLE["logs"])

    if e.status == 401:
        return Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Sentinel authentication failed — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary="Check SENTINEL_TENANT_ID / SENTINEL_CLIENT_ID / "
                "SENTINEL_CLIENT_SECRET in .env.sentinel.",
                confidence="high",
            ),
        )
    if e.status == 403:
        return Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Sentinel permission missing — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary=f"Grant the app the '{role}' role on the Log Analytics "
                "workspace resource, then retry.",
                confidence="high",
            ),
        )
    if e.status == 429:
        return Finding.rate_limited("sentinel", capability)
    if e.status in (502, 503):
        return Finding.api_unavailable("sentinel", capability, e.status)
    if e.status == 504:
        return Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Sentinel query timed out — {capability}",
            recommended_action=RecommendedAction(
                summary="Narrow the search: reduce hours, or supply an indicator "
                "so the query filters before it scans.",
                confidence="high",
            ),
        )
    if e.status == 400:
        # The KQL was rejected. Hand the sanitized reason back so the model can
        # correct itself instead of blindly retrying the same broken query.
        return Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Sentinel rejected the query — {capability}: {e.message[:300]}",
            recommended_action=RecommendedAction(
                summary="The column or operator does not exist in this workspace. "
                "Use list_data_sources to see which tables exist, then retry.",
                confidence="medium",
            ),
        )
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/tests/test_errors.py -v && uv run mypy .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add servers/sentinel-mcp/f0_sentinel_mcp/errors.py servers/sentinel-mcp/tests/test_errors.py
git commit -m "feat(sentinel): map API errors to graceful findings, per-half role hints"
```

---

### Task 4: `normalize.py` — the vendor vocabulary layer

**Files:**
- Create: `servers/sentinel-mcp/f0_sentinel_mcp/normalize.py`
- Test: `servers/sentinel-mcp/tests/test_normalize.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `ACTIONS: tuple[str, ...]`, `SURFACES: tuple[str, ...]`, `WORKLOADS: tuple[str, ...]`
  - `Surface` dataclass: `table: str`, `action_field: str`, `action_map: dict[str, tuple[str, ...]]`, `indicator_fields: tuple[str, ...]`, `junk: tuple[str, ...]`, `project: tuple[str, ...]`
  - `SURFACE_SPECS: dict[str, Surface]` (keys `"firewall"`, `"dns"`, `"web"`, `"vpn"`)
  - `clamp_hours(hours: object, retention_days: int) -> float`
  - `timespan(hours: float) -> str`
  - `action_clause(spec: Surface, action: str) -> str`
  - `hygiene_clause(spec: Surface) -> str`
  - `indicator_clause(spec: Surface, indicator: str) -> str`
  - `validate_indicator(indicator: str, kind: str) -> bool` where `kind` is `"net"` or `"domain"`
  - `IP_RE`, `PORT_RE`, `DOMAIN_RE`, `WORD_RE`, `UPN_RE`

- [ ] **Step 1: Write the failing tests**

`servers/sentinel-mcp/tests/test_normalize.py`:

```python
"""Contract tests for the vendor normalization layer.

The action vocabulary is the small-model contract: raw DeviceAction has 15+
mixed-case values (Accept/blocked/Drop/Detect/detected/Bypass/crash/...), which
is exactly the oversized enum CLAUDE.md forbids exposing.
"""
from __future__ import annotations

import pytest
from f0_sentinel_mcp import normalize as n


def test_clamp_hours_bounds_to_retention():
    assert n.clamp_hours(24, 30) == 24.0
    assert n.clamp_hours(10_000, 30) == 720.0      # 30d retention
    assert n.clamp_hours(10_000, 90) == 2160.0     # honours a longer retention
    assert n.clamp_hours(0, 30) == 1.0
    assert n.clamp_hours(-5, 30) == 1.0
    assert n.clamp_hours("banana", 30) == 24.0     # unparseable -> default


def test_timespan_is_iso8601_duration():
    assert n.timespan(24) == "PT24H"
    assert n.timespan(0.5) == "PT0.5H"


def test_action_clause_maps_semantics_to_messy_vendor_values():
    fw = n.SURFACE_SPECS["firewall"]
    blocked = n.action_clause(fw, "blocked")
    # Case-insensitive `in~` is what absorbs Drop vs blocked vs BLOCK.
    assert "in~" in blocked
    assert "Drop" in blocked and "blocked" in blocked
    assert "Accept" not in blocked


def test_action_clause_any_emits_no_filter():
    assert n.action_clause(n.SURFACE_SPECS["firewall"], "any") == ""


def test_every_surface_supports_allowed_and_blocked():
    for name, spec in n.SURFACE_SPECS.items():
        assert "allowed" in spec.action_map, name
        assert "blocked" in spec.action_map, name


def test_umbrella_surfaces_use_three_different_field_names():
    # Verified live 2026-08-11: the same concept is Action_s / Verdict_s /
    # verdict_s across three tables. This test pins that so a refactor that
    # "tidies" them into one name fails loudly.
    assert n.SURFACE_SPECS["dns"].action_field == "Action_s"
    assert n.SURFACE_SPECS["web"].action_field == "Verdict_s"
    assert n.SURFACE_SPECS["vpn"].action_field == "Event_Type_s"


def test_hygiene_clause_filters_ingested_csv_header_rows():
    # The tenant's Umbrella connectors ingest their header row as data.
    clause = n.hygiene_clause(n.SURFACE_SPECS["dns"])
    assert "Action" in clause and "!in~" in clause


def test_hygiene_clause_empty_when_surface_has_no_junk():
    assert n.hygiene_clause(n.SURFACE_SPECS["firewall"]) == ""


def test_validate_indicator_net_accepts_ip_and_port_rejects_domain():
    assert n.validate_indicator("10.1.2.3", "net") is True
    assert n.validate_indicator("443", "net") is True
    assert n.validate_indicator("fe80::1", "net") is True
    # The firewall table has a 0.08% RequestURL fill rate — a domain here would
    # silently return nothing, so it is rejected loudly instead.
    assert n.validate_indicator("evil.com", "net") is False


def test_validate_indicator_domain_accepts_host_rejects_injection():
    assert n.validate_indicator("evil.com", "domain") is True
    assert n.validate_indicator("*.evil.com", "domain") is True
    assert n.validate_indicator('a" or 1==1 //', "domain") is False
    assert n.validate_indicator("a\\\" | project *", "domain") is False


def test_indicator_clause_quotes_and_targets_surface_fields():
    dns = n.SURFACE_SPECS["dns"]
    clause = n.indicator_clause(dns, "evil.com")
    assert "Domain_s" in clause
    assert '"evil.com"' in clause


def test_indicator_clause_empty_indicator_yields_no_filter():
    assert n.indicator_clause(n.SURFACE_SPECS["dns"], "") == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_normalize.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'f0_sentinel_mcp.normalize'`

- [ ] **Step 3: Implement**

`servers/sentinel-mcp/f0_sentinel_mcp/normalize.py`:

```python
"""Collapse three vendors' inconsistent fields into one small-model vocabulary.

This module is the server's actual product. Raw `DeviceAction` on the CEF table
carries 15+ mixed-case, mixed-semantic values (Accept, blocked, Drop, Detect,
detected, Bypass, "Failed Log In", crash, RADIUS-auth-failure, negotiate,
DHCP-no-response, ...), and the three Cisco Umbrella tables express the same
allow/block concept under three different field NAMES in three different
CASINGS (Action_s=Allowed/Blocked, Verdict_s=ALLOWED/BLOCKED,
verdict_s=ALLOW/BLOCK). Exposing any of that to a small model is the
"40-value enum the model picks wrong from" failure CLAUDE.md names explicitly.

Everything here is table-driven so a new vendor is a SURFACE_SPECS entry, not a
tool rewrite. All values verified against live data 2026-08-11.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

ACTIONS = ("allowed", "blocked", "detected", "any")
SURFACES = ("dns", "web", "vpn")
WORKLOADS = ("sharepoint", "onedrive", "exchange", "teams", "any")

DEFAULT_HOURS = 24.0

# Strict charsets for anything spliced into KQL. httpx does not escape a query
# body, so these are the injection boundary as well as small-model guidance.
IP_RE = re.compile(r"^[0-9a-fA-F:.]{1,45}$")
PORT_RE = re.compile(r"^\d{1,5}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9._*-]{1,253}$")
WORD_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
UPN_RE = re.compile(r"^[A-Za-z0-9@._-]{1,128}$")


@dataclass(frozen=True)
class Surface:
    """One queryable telemetry surface: its table, action vocabulary, and filters."""

    table: str
    action_field: str
    action_map: dict[str, tuple[str, ...]]
    indicator_fields: tuple[str, ...]
    project: tuple[str, ...]
    indicator_kind: str = "domain"
    junk: tuple[str, ...] = field(default_factory=tuple)


SURFACE_SPECS: dict[str, Surface] = {
    # Check Point VPN-1/FireWall-1 dominates this table; Fortinet FortiGate also
    # lands here. Live fill rates (824K rows/1h): SourceIP 99.8%, DestinationIP
    # 98.7%, DestinationPort 96.6% -- but RequestURL 0.08%, SourceUserName 0.28%,
    # DestinationHostName 0.57%. Hence indicator_kind="net": IP/port only.
    "firewall": Surface(
        table="CommonSecurityLog",
        action_field="DeviceAction",
        action_map={
            "allowed": ("Accept", "Bypass"),
            "blocked": ("Drop", "blocked", "Reject"),
            "detected": ("Detect", "detected"),
        },
        indicator_fields=("SourceIP", "DestinationIP", "DestinationPort"),
        project=(
            "TimeGenerated", "DeviceVendor", "DeviceProduct", "DeviceAction",
            "SourceIP", "DestinationIP", "DestinationPort", "Activity",
        ),
        indicator_kind="net",
    ),
    "dns": Surface(
        table="Cisco_Umbrella_dns_CL",
        action_field="Action_s",
        action_map={"allowed": ("Allowed",), "blocked": ("Blocked",)},
        indicator_fields=("Domain_s",),
        project=(
            "TimeGenerated", "Action_s", "Domain_s", "Categories_s",
            "InternalIp_s", "ExternalIp_s", "Identities_s", "QueryType_s",
        ),
        junk=("Action",),
    ),
    "web": Surface(
        table="Cisco_Umbrella_proxy_CL",
        action_field="Verdict_s",
        action_map={"allowed": ("ALLOWED",), "blocked": ("BLOCKED",)},
        indicator_fields=("URL_s", "Destination_IP_s"),
        project=(
            "TimeGenerated", "Verdict_s", "URL_s", "Categories_s",
            "Internal_IP_s", "Identities_s", "File_Name_s", "SHA_SHA256_s",
        ),
        junk=("Action",),
    ),
    "vpn": Surface(
        table="Cisco_Umbrella_ravpnlogs_CL",
        action_field="Event_Type_s",
        action_map={"allowed": ("connected",), "blocked": ("failed",)},
        indicator_fields=("User_ID_s", "Public_IP_s", "Assigned_IP_s"),
        project=(
            "TimeGenerated", "Event_Type_s", "User_ID_s", "Public_IP_s",
            "Assigned_IP_s", "VPN_Profile_s", "OS_Version_s", "Failed_Reasons_s",
        ),
    ),
}


def clamp_hours(hours: object, retention_days: int) -> float:
    """Bound a lookback to [1, retention_days * 24].

    Beyond retention a query returns nothing, which a model reads as "no
    activity" — a confidently wrong answer. Clamping converts that into an
    honest, in-range one.
    """
    try:
        h = float(hours)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return DEFAULT_HOURS
    if h < 1:
        return 1.0
    return min(h, float(retention_days * 24))


def timespan(hours: float) -> str:
    """ISO-8601 duration for the query API's `timespan` parameter."""
    return f"PT{hours:g}H"


def _kql_list(values: tuple[str, ...]) -> str:
    return ", ".join(f'"{v}"' for v in values)


def action_clause(spec: Surface, action: str) -> str:
    """`| where <field> in~ (...)` for a semantic action, or "" for `any`.

    `in~` is case-insensitive, which is what absorbs ALLOW vs ALLOWED vs Allowed
    without a per-vendor casing table.
    """
    values = spec.action_map.get(action)
    if not values:
        return ""
    return f"| where {spec.action_field} in~ ({_kql_list(values)})"


def hygiene_clause(spec: Surface) -> str:
    """Drop CSV header rows that the connector ingested as data.

    Verified 2026-08-11: Action_s == "Action" (~2.3K rows/day),
    Verdict_s == "Action" (~1.2K/day). Without this every "top values" answer
    carries a phantom bucket.
    """
    if not spec.junk:
        return ""
    return f"| where {spec.action_field} !in~ ({_kql_list(spec.junk)})"


def validate_indicator(indicator: str, kind: str) -> bool:
    """True if the indicator is safe to splice into KQL AND meaningful for `kind`."""
    if not indicator:
        return True
    if kind == "net":
        return bool(IP_RE.match(indicator) or PORT_RE.match(indicator))
    return bool(DOMAIN_RE.match(indicator))


def indicator_clause(spec: Surface, indicator: str) -> str:
    """`| where <f1> has "x" or <f2> has "x" ...` across the surface's fields.

    Callers MUST have run validate_indicator first; this function assumes a
    charset with no quotes or backslashes.
    """
    if not indicator:
        return ""
    if spec.indicator_kind == "net" and PORT_RE.match(indicator):
        return f'| where DestinationPort == {int(indicator)}'
    terms = " or ".join(f'{f} has "{indicator}"' for f in spec.indicator_fields)
    return f"| where {terms}"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/tests/test_normalize.py -v && uv run mypy . && uv run ruff check servers/sentinel-mcp`
Expected: PASS

> `vpn`'s `Event_Type_s` values (`connected`/`failed`) are the one unverified guess in this table — the RA-VPN table had only ~10K rows and was not sampled for that field. Task 15 confirms it live and fixes forward.

- [ ] **Step 5: Commit**

```bash
git add servers/sentinel-mcp/f0_sentinel_mcp/normalize.py servers/sentinel-mcp/tests/test_normalize.py
git commit -m "feat(sentinel): vendor normalization layer with verified action vocabulary"
```

---

### Task 5: `probe.py` + the `list_data_sources` tool

**Files:**
- Create: `servers/sentinel-mcp/f0_sentinel_mcp/probe.py`, `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`, `servers/sentinel-mcp/tests/conftest.py`, `servers/sentinel-mcp/tests/test_tools.py`

**Interfaces:**
- Consumes: `SentinelClient` (Task 2), `map_sentinel_error` (Task 3), `normalize` (Task 4).
- Produces:
  - `probe.probed_tables(client) -> set[str]` (cached per workspace for the process)
  - `probe.reset_cache() -> None`
  - `probe.require_table(client, table: str, human: str) -> Finding | None`
  - `tools.list_data_sources(client) -> list[Finding]`

- [ ] **Step 1: Write the failing tests**

`servers/sentinel-mcp/tests/conftest.py`:

```python
"""Test fixtures for the Sentinel server."""
from __future__ import annotations

import pytest
from f0_sentinel_mcp import probe


class FakeClient:
    """Fake SentinelClient: canned KQL rows by substring, or a configured error."""

    def __init__(self, rows=None, arm=None, raise_on=None, retention_days=30, has_arm=True):
        self._rows = rows or {}
        self._arm = arm or {}
        self._raise = raise_on or {}
        self.retention_days = retention_days
        self.has_arm = has_arm
        self.workspace_id = "ws-test"
        self.queries: list[str] = []

    async def query(self, kql, timespan):
        self.queries.append(kql)
        for needle, err in self._raise.items():
            if needle in kql:
                raise err
        # Longest-match-first so a specific fixture beats a generic one.
        for needle, rows in sorted(self._rows.items(), key=lambda kv: -len(kv[0])):
            if needle in kql:
                return rows
        return []

    async def arm_list(self, resource):
        for needle, err in self._raise.items():
            if needle == resource:
                raise err
        return self._arm.get(resource, [])


@pytest.fixture
def fake():
    return FakeClient


@pytest.fixture(autouse=True)
def _reset_probe_cache():
    """The capability probe caches per workspace for the process lifetime; clear
    it around every test so one test's table set cannot leak into the next."""
    probe.reset_cache()
    yield
    probe.reset_cache()
```

`servers/sentinel-mcp/tests/test_tools.py` (first tests — this file grows in later tasks):

```python
"""Contract tests for the Sentinel tools (fake client, no network)."""
from __future__ import annotations

from f0_sectools_core.auth.graph import GraphError
from f0_sentinel_mcp import probe, tools

USAGE = "Usage"
_TABLES = [
    {"DataType": "CommonSecurityLog", "GB": 250.45},
    {"DataType": "Cisco_Umbrella_dns_CL", "GB": 2.8},
    {"DataType": "OfficeActivity", "GB": 4.1},
    {"DataType": "SecurityIncident", "GB": 0.0},
]


async def test_probe_returns_table_names(fake):
    client = fake(rows={USAGE: _TABLES})
    assert await probe.probed_tables(client) == {
        "CommonSecurityLog", "Cisco_Umbrella_dns_CL", "OfficeActivity", "SecurityIncident",
    }


async def test_probe_is_cached_for_the_process(fake):
    client = fake(rows={USAGE: _TABLES})
    await probe.probed_tables(client)
    await probe.probed_tables(client)
    assert len([q for q in client.queries if "Usage" in q]) == 1


async def test_require_table_returns_none_when_present(fake):
    client = fake(rows={USAGE: _TABLES})
    assert await probe.require_table(client, "CommonSecurityLog", "firewall (CEF)") is None


async def test_require_table_returns_posture_not_empty_list_when_absent(fake):
    # An empty list reads as "no matching traffic". "This workspace has no
    # firewall feed" is a materially different answer and must be said out loud.
    client = fake(rows={USAGE: _TABLES})
    f = await probe.require_table(client, "Syslog", "syslog")
    assert f is not None
    assert f.finding_type.value == "posture"
    assert "syslog" in f.title.lower()


async def test_list_data_sources_returns_one_finding_per_table_plus_summary(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.list_data_sources(client)
    titles = " ".join(f.title for f in out)
    assert "CommonSecurityLog" in titles
    assert any(f.finding_type.value == "posture" for f in out)


async def test_list_data_sources_labels_families(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.list_data_sources(client)
    ev = {e.key: e.value for f in out for e in f.evidence}
    assert ev.get("family") in {"firewall", "dns_web", "office", "incident", "custom", "identity"}


async def test_list_data_sources_maps_403_to_posture(fake):
    client = fake(raise_on={USAGE: GraphError(403, "forbidden")})
    out = await tools.list_data_sources(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_tools.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'f0_sentinel_mcp.probe'`

- [ ] **Step 3: Implement the probe**

`servers/sentinel-mcp/f0_sentinel_mcp/probe.py`:

```python
"""Runtime capability probe: which tables does THIS workspace actually have?

Built on the `Usage` table, deliberately NOT on the `dataConnectors` management
API. Measured 2026-08-11 on the validation tenant: `dataConnectors` reported a
single connector (Office365) while at least six sources were actively ingesting
— AMA/DCR and codeless connectors never register there. A coverage answer built
on that API would systematically understate reality.

Cached per workspace for the process lifetime: reads are idempotent and the set
of ingesting tables does not change within a session.
"""
from __future__ import annotations

from typing import Any

from f0_sectools_core.schema.findings import (
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

_CACHE: dict[str, set[str]] = {}

# No IsBillable filter: free-tier tables (SecurityIncident, SecurityAlert,
# OfficeActivity on some SKUs) are absent from a billable-only Usage roll-up,
# and those are exactly the tables three of our tools depend on.
_USAGE_KQL = (
    "Usage | where TimeGenerated > ago(30d) "
    "| summarize GB=round(sum(Quantity)/1024, 3) by DataType | sort by GB desc"
)


async def probed_tables(client: Any) -> set[str]:
    """The set of table names with data in the last 30d. Cached per workspace."""
    key = str(getattr(client, "workspace_id", "default"))
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    rows = await client.query(_USAGE_KQL, "P30D")
    tables = {str(r.get("DataType", "")) for r in rows if r.get("DataType")}
    _CACHE[key] = tables
    return tables


def reset_cache() -> None:
    """Clear the probe cache (tests, and the live smoke script between runs)."""
    _CACHE.clear()


async def require_table(client: Any, table: str, human: str) -> Finding | None:
    """None if the workspace has `table`, else a posture finding saying so.

    Returning a posture finding rather than an empty list is the whole point: an
    empty list reads as "nothing matched your search", which is a different — and
    wrong — answer from "this workspace has no such feed".
    """
    if table in await probed_tables(client):
        return None
    return Finding(
        source="sentinel",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"No {human} data in this workspace ({table} is not ingesting)",
        recommended_action=RecommendedAction(
            summary="Use list_data_sources to see which telemetry this workspace "
            "does have, then pick a tool that matches it.",
            confidence="high",
        ),
    )
```

- [ ] **Step 4: Implement `list_data_sources`**

Create `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`:

```python
"""Microsoft Sentinel read tools -> findings.

Read-only. Every API failure maps to a posture finding, never an exception.
Table and field names were validated against a live workspace on 2026-08-11;
dict access is defensive throughout because the next workspace differs.
"""
from __future__ import annotations

from typing import Any

from f0_sectools_core.auth.graph import GraphError
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from .errors import map_sentinel_error
from .probe import probed_tables

_FAMILY_PREFIX = (
    ("CommonSecurityLog", "firewall"),
    ("Cisco_Umbrella", "dns_web"),
    ("OfficeActivity", "office"),
    ("SecurityIncident", "incident"),
    ("SecurityAlert", "incident"),
    ("SigninLogs", "identity"),
    ("AAD", "identity"),
    ("IdentityInfo", "identity"),
    ("BehaviorAnalytics", "identity"),
    ("Syslog", "firewall"),
)


def _family(table: str) -> str:
    for prefix, fam in _FAMILY_PREFIX:
        if table.startswith(prefix):
            return fam
    return "custom"


def _bad_arg(name: str, value: str, accepted: str) -> Finding:
    """A rejected argument is reported, never silently dropped from the filter."""
    return Finding(
        source="sentinel",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Unsupported {name} '{value[:60]}'",
        recommended_action=RecommendedAction(summary=f"Accepted: {accepted}.", confidence="high"),
    )


async def list_data_sources(client: Any) -> list[Finding]:
    """What telemetry this workspace actually ingests (30d), by volume."""
    cap = "Sentinel data sources"
    try:
        tables = sorted(await probed_tables(client))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not tables:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title="No telemetry found in this Sentinel workspace (last 30 days)",
                recommended_action=RecommendedAction(
                    summary="Check that connectors are configured and the app has "
                    "the Log Analytics Reader role.",
                ),
            )
        ]

    findings = [
        Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"{len(tables)} tables ingesting in this Sentinel workspace (30d)",
            entity=Entity(kind=EntityKind.tenant, id="sentinel"),
            evidence=[Evidence(key="table_count", value=str(len(tables)))],
        )
    ]
    for t in tables:
        findings.append(
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"{t} — ingesting",
                entity=Entity(kind=EntityKind.tenant, id=t, name=t),
                evidence=[Evidence(key="family", value=_family(t))],
            )
        )
    return findings
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/tests/ -v && uv run mypy . && uv run ruff check servers/sentinel-mcp`
Expected: PASS. Ruff must be clean here: import only what this task uses — later
tasks extend the block as they need names.

- [ ] **Step 6: Commit**

```bash
git add servers/sentinel-mcp/
git commit -m "feat(sentinel): Usage-based capability probe and list_data_sources"
```

---

### Task 6: `hunt_firewall`

**Files:**
- Modify: `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`, `servers/sentinel-mcp/tests/test_tools.py`

**Interfaces:**
- Produces: `tools.hunt_firewall(client, action: str = "any", indicator: str = "", hours: float = 24, limit: int = 25) -> list[Finding]`
- Also produces the shared helper `_run_surface(client, spec, cap, human, action, indicator, hours, limit) -> list[Finding]` used by Task 7.

- [ ] **Step 1: Write the failing tests**

Append to `servers/sentinel-mcp/tests/test_tools.py`:

```python
CEF = "CommonSecurityLog"


async def test_hunt_firewall_without_indicator_is_aggregate_only(fake):
    # 112M rows/7d: an unfiltered row dump is a cost and context-window incident.
    client = fake(rows={
        USAGE: _TABLES,
        CEF: [{"DeviceAction": "Drop", "DestinationPort": 445, "Events": 900}],
    })
    out = await tools.hunt_firewall(client, action="blocked")
    kql = [q for q in client.queries if CEF in q][0]
    assert "summarize" in kql
    assert "| take" not in kql.split("summarize")[0]
    assert out and all(f.finding_type.value in {"hunt_result", "posture"} for f in out)


async def test_hunt_firewall_with_indicator_samples_rows(fake):
    client = fake(rows={
        USAGE: _TABLES,
        CEF: [{"TimeGenerated": "2026-08-11T00:00:00Z", "SourceIP": "10.1.2.3",
               "DestinationIP": "8.8.8.8", "DestinationPort": 53, "DeviceAction": "Accept"}],
    })
    out = await tools.hunt_firewall(client, indicator="10.1.2.3")
    kql = [q for q in client.queries if CEF in q][0]
    assert '"10.1.2.3"' in kql
    assert "summarize" not in kql
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_hunt_firewall_time_predicate_comes_first(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []})
    await tools.hunt_firewall(client, hours=6)
    kql = [q for q in client.queries if CEF in q][0]
    body = kql.split("|", 1)[1]
    assert body.strip().startswith("where TimeGenerated > ago(")


async def test_hunt_firewall_clamps_hours_to_retention(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []}, retention_days=30)
    await tools.hunt_firewall(client, hours=99999)
    kql = [q for q in client.queries if CEF in q][0]
    assert "ago(720h)" in kql


async def test_hunt_firewall_rejects_domain_indicator(fake):
    # RequestURL fill rate is 0.08% on this table — a domain filter returns
    # nothing, so say so instead of answering "no activity found".
    client = fake(rows={USAGE: _TABLES, CEF: []})
    out = await tools.hunt_firewall(client, indicator="evil.com")
    assert len(out) == 1
    assert out[0].finding_type.value == "posture"
    assert "hunt_dns_web" in (out[0].recommended_action.summary if out[0].recommended_action else "")


async def test_hunt_firewall_missing_table_returns_posture(fake):
    client = fake(rows={USAGE: [{"DataType": "Syslog", "GB": 1.0}]})
    out = await tools.hunt_firewall(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert "firewall" in out[0].title.lower()


async def test_hunt_firewall_action_blocked_maps_to_vendor_values(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []})
    await tools.hunt_firewall(client, action="blocked")
    kql = [q for q in client.queries if CEF in q][0]
    assert "Drop" in kql and "Accept" not in kql


async def test_hunt_firewall_bad_action_reports_rather_than_ignoring(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []})
    out = await tools.hunt_firewall(client, action="allowedd")
    assert len(out) == 1 and out[0].finding_type.value == "posture"


async def test_hunt_firewall_429_maps_to_rate_limited(fake):
    client = fake(rows={USAGE: _TABLES}, raise_on={CEF: GraphError(429, "slow down")})
    out = await tools.hunt_firewall(client)
    assert len(out) == 1 and "Rate limited" in out[0].title
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_tools.py -k firewall -v`
Expected: FAIL with `AttributeError: module 'f0_sentinel_mcp.tools' has no attribute 'hunt_firewall'`

- [ ] **Step 3: Implement**

Extend the import block at the top of
`servers/sentinel-mcp/f0_sentinel_mcp/tools.py` — Task 5 imported only what it
used, so this task adds the three names it is the first to need (keep the
block isort-ordered; `ruff check` enforces it):

```python
from f0_sectools_core.paging import clamp_limit, more_available_finding
# ...
from . import normalize as n
from .probe import probed_tables, require_table
```

Then append to `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`:

```python
_INDICATOR_HELP = {
    "net": "an IP address or a port number (this table carries no URLs or "
    "usernames — for domains and URLs use hunt_dns_web)",
    "domain": "a domain, URL fragment, or IP",
}


def _rows_to_findings(rows: list[dict[str, Any]], title_key: str, limit: int) -> list[Finding]:
    out: list[Finding] = []
    for r in rows[:limit]:
        out.append(
            Finding(
                source="sentinel",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=str(r.get(title_key) or "event"),
                evidence=[
                    Evidence(key=str(k), value=str(v))
                    for k, v in r.items()
                    if v is not None and str(v) != ""
                ][:12],
                observed_at=str(r.get("TimeGenerated") or "") or None,
            )
        )
    return out


async def _run_surface(
    client: Any,
    spec: n.Surface,
    cap: str,
    human: str,
    action: str,
    indicator: str,
    hours: float,
    limit: int,
) -> list[Finding]:
    """Shared execution path for every KQL telemetry surface.

    Bounding rules live here so no individual tool can forget one: time
    predicate first, retention clamp, limit clamp, and aggregate-only whenever
    no indicator narrows the scan.
    """
    if action not in n.ACTIONS:
        return [_bad_arg("action", action, ", ".join(n.ACTIONS))]
    if not n.validate_indicator(indicator, spec.indicator_kind):
        return [_bad_arg("indicator", indicator, _INDICATOR_HELP[spec.indicator_kind])]

    missing = await require_table(client, spec.table, human)
    if missing:
        return [missing]

    hours = n.clamp_hours(hours, client.retention_days)
    limit = clamp_limit(limit)

    parts = [
        spec.table,
        f"| where TimeGenerated > ago({hours:g}h)",
        n.hygiene_clause(spec),
        n.action_clause(spec, action),
        n.indicator_clause(spec, indicator),
    ]
    if indicator:
        parts.append(f"| project {', '.join(spec.project)}")
        parts.append(f"| order by TimeGenerated desc | take {limit}")
    else:
        # No indicator -> aggregate. Never dump rows from a table this large.
        parts.append(
            f"| summarize Events=count() by {spec.action_field}, {spec.indicator_fields[0]}"
        )
        parts.append(f"| top {limit} by Events desc")
    kql = " ".join(p for p in parts if p)

    try:
        rows = await client.query(kql, n.timespan(hours))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not rows:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=f"No {human} activity matched in the last {hours:g}h",
                recommended_action=RecommendedAction(
                    summary="Widen hours, relax action, or drop the indicator.",
                ),
            )
        ]

    title_key = spec.indicator_fields[0] if indicator else spec.action_field
    findings = _rows_to_findings(rows, title_key, limit)
    if len(rows) >= limit:
        findings.append(
            more_available_finding(
                "sentinel", shown=len(findings),
                hint="Narrow with an indicator or a shorter hours window.",
            )
        )
    return findings


async def hunt_firewall(
    client: Any,
    action: str = "any",
    indicator: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """Firewall traffic from the CEF table (Check Point / Fortinet)."""
    return await _run_surface(
        client, n.SURFACE_SPECS["firewall"],
        cap="Sentinel firewall telemetry", human="firewall (CEF)",
        action=action, indicator=indicator, hours=hours, limit=limit,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/tests/ -v && uv run mypy .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add servers/sentinel-mcp/
git commit -m "feat(sentinel): hunt_firewall with aggregate-only default and IP/port guard"
```

---

### Task 7: `hunt_dns_web`

**Files:**
- Modify: `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`, `servers/sentinel-mcp/tests/test_tools.py`

**Interfaces:**
- Consumes: `_run_surface` (Task 6), `n.SURFACE_SPECS` (Task 4).
- Produces: `tools.hunt_dns_web(client, surface: str = "dns", action: str = "any", indicator: str = "", hours: float = 24, limit: int = 25) -> list[Finding]`

- [ ] **Step 1: Write the failing tests**

Append to `servers/sentinel-mcp/tests/test_tools.py`:

```python
DNS = "Cisco_Umbrella_dns_CL"
WEB = "Cisco_Umbrella_proxy_CL"


async def test_hunt_dns_web_selects_table_by_surface(fake):
    client = fake(rows={USAGE: _TABLES + [{"DataType": WEB, "GB": 0.9}], DNS: [], WEB: []})
    await tools.hunt_dns_web(client, surface="dns")
    await tools.hunt_dns_web(client, surface="web")
    assert any(DNS in q for q in client.queries)
    assert any(WEB in q for q in client.queries)


async def test_hunt_dns_web_filters_ingested_header_rows(fake):
    # Action_s == "Action" is a CSV header the connector ingested as data.
    client = fake(rows={USAGE: _TABLES, DNS: []})
    await tools.hunt_dns_web(client, surface="dns")
    kql = [q for q in client.queries if DNS in q][0]
    assert '!in~ ("Action")' in kql


async def test_hunt_dns_web_accepts_domain_indicator(fake):
    client = fake(rows={USAGE: _TABLES, DNS: [{"Domain_s": "evil.com", "Action_s": "Blocked"}]})
    out = await tools.hunt_dns_web(client, surface="dns", indicator="evil.com", action="blocked")
    kql = [q for q in client.queries if DNS in q][0]
    assert '"evil.com"' in kql and "Blocked" in kql
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_hunt_dns_web_rejects_kql_injection_in_indicator(fake):
    client = fake(rows={USAGE: _TABLES, DNS: []})
    out = await tools.hunt_dns_web(client, surface="dns", indicator='x" | project *; //')
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert not [q for q in client.queries if DNS in q]


async def test_hunt_dns_web_bad_surface_reports(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.hunt_dns_web(client, surface="carrier-pigeon")
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert "dns" in (out[0].recommended_action.summary if out[0].recommended_action else "")


async def test_hunt_dns_web_missing_umbrella_table_returns_posture(fake):
    client = fake(rows={USAGE: [{"DataType": "CommonSecurityLog", "GB": 1.0}]})
    out = await tools.hunt_dns_web(client, surface="dns")
    assert len(out) == 1 and out[0].finding_type.value == "posture"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_tools.py -k dns_web -v`
Expected: FAIL with `AttributeError: module 'f0_sentinel_mcp.tools' has no attribute 'hunt_dns_web'`

- [ ] **Step 3: Implement**

Append to `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`:

```python
_SURFACE_HUMAN = {
    "dns": "DNS (Cisco Umbrella)",
    "web": "web proxy (Cisco Umbrella)",
    "vpn": "remote-access VPN (Cisco Umbrella)",
}


async def hunt_dns_web(
    client: Any,
    surface: str = "dns",
    action: str = "any",
    indicator: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """DNS / web-proxy / RA-VPN activity from the Cisco Umbrella tables."""
    if surface not in n.SURFACES:
        return [_bad_arg("surface", surface, ", ".join(n.SURFACES))]
    return await _run_surface(
        client, n.SURFACE_SPECS[surface],
        cap=f"Sentinel {surface} telemetry", human=_SURFACE_HUMAN[surface],
        action=action, indicator=indicator, hours=hours, limit=limit,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/tests/ -v && uv run mypy .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add servers/sentinel-mcp/
git commit -m "feat(sentinel): hunt_dns_web across Umbrella dns/web/vpn surfaces"
```

---

### Task 8: `search_office_activity`

**Files:**
- Modify: `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`, `servers/sentinel-mcp/tests/test_tools.py`

**Interfaces:**
- Produces: `tools.search_office_activity(client, workload: str = "any", operation: str = "", user: str = "", hours: float = 24, limit: int = 25) -> list[Finding]`

- [ ] **Step 1: Write the failing tests**

Append to `servers/sentinel-mcp/tests/test_tools.py`:

```python
OA = "OfficeActivity"


async def test_search_office_activity_without_operation_returns_operation_breakdown(fake):
    # Discovery in ONE call: the model learns valid operation names instead of
    # guessing them, which is the two-call dance purview's audit search forces.
    client = fake(rows={USAGE: _TABLES, OA: [{"Operation": "FileDownloaded", "Events": 48163}]})
    out = await tools.search_office_activity(client)
    kql = [q for q in client.queries if OA in q][0]
    assert "summarize" in kql and "by Operation" in kql
    assert any("FileDownloaded" in f.title for f in out)


async def test_search_office_activity_with_operation_returns_events(fake):
    client = fake(rows={USAGE: _TABLES, OA: [
        {"TimeGenerated": "2026-08-11T00:00:00Z", "Operation": "FileDownloaded",
         "UserId": "a@b.com", "OfficeWorkload": "OneDrive"},
    ]})
    out = await tools.search_office_activity(client, operation="FileDownloaded")
    kql = [q for q in client.queries if OA in q][0]
    assert 'Operation =~ "FileDownloaded"' in kql
    assert "summarize" not in kql
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_search_office_activity_workload_filter(fake):
    client = fake(rows={USAGE: _TABLES, OA: []})
    await tools.search_office_activity(client, workload="exchange", operation="MailItemsAccessed")
    kql = [q for q in client.queries if OA in q][0]
    assert 'OfficeWorkload =~ "Exchange"' in kql


async def test_search_office_activity_any_workload_emits_no_workload_filter(fake):
    client = fake(rows={USAGE: _TABLES, OA: []})
    await tools.search_office_activity(client, workload="any", operation="FileAccessed")
    kql = [q for q in client.queries if OA in q][0]
    assert "OfficeWorkload =~" not in kql


async def test_search_office_activity_user_filter_validated(fake):
    client = fake(rows={USAGE: _TABLES, OA: []})
    ok = await tools.search_office_activity(client, user="a@b.com", operation="FileAccessed")
    assert not (len(ok) == 1 and ok[0].title.startswith("Unsupported"))
    bad = await tools.search_office_activity(client, user='a" or 1==1')
    assert len(bad) == 1 and bad[0].finding_type.value == "posture"


async def test_search_office_activity_bad_workload_reports(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.search_office_activity(client, workload="yammer")
    assert len(out) == 1 and out[0].finding_type.value == "posture"


async def test_search_office_activity_missing_table_returns_posture(fake):
    client = fake(rows={USAGE: [{"DataType": "Syslog", "GB": 1.0}]})
    out = await tools.search_office_activity(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_tools.py -k office -v`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Implement**

Append to `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`:

```python
# Live-verified 2026-08-11: OfficeWorkload values are these exact strings.
_WORKLOAD_VALUE = {
    "sharepoint": "SharePoint",
    "onedrive": "OneDrive",
    "exchange": "Exchange",
    "teams": "MicrosoftTeams",
}
_OA_PROJECT = (
    "TimeGenerated", "OfficeWorkload", "Operation", "UserId",
    "ClientIP", "OfficeObjectId", "ResultStatus",
)


async def search_office_activity(
    client: Any,
    workload: str = "any",
    operation: str = "",
    user: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """Microsoft 365 audit activity from OfficeActivity (fast path vs. Purview)."""
    cap = "Sentinel Microsoft 365 activity"
    if workload not in n.WORKLOADS:
        return [_bad_arg("workload", workload, ", ".join(n.WORKLOADS))]
    if operation and not n.WORD_RE.match(operation):
        return [_bad_arg("operation", operation, "an exact operation name, e.g. FileDownloaded")]
    if user and not n.UPN_RE.match(user):
        return [_bad_arg("user", user, "a UPN, e.g. someone@contoso.com")]

    missing = await require_table(client, "OfficeActivity", "Microsoft 365 audit (OfficeActivity)")
    if missing:
        return [missing]

    hours = n.clamp_hours(hours, client.retention_days)
    limit = clamp_limit(limit)

    parts = ["OfficeActivity", f"| where TimeGenerated > ago({hours:g}h)"]
    if workload != "any":
        parts.append(f'| where OfficeWorkload =~ "{_WORKLOAD_VALUE[workload]}"')
    if user:
        parts.append(f'| where UserId =~ "{user}"')
    if operation:
        parts.append(f'| where Operation =~ "{operation}"')
        parts.append(f"| project {', '.join(_OA_PROJECT)}")
        parts.append(f"| order by TimeGenerated desc | take {limit}")
    else:
        # Discovery mode: hand back the operation vocabulary so the model can
        # pick a real value rather than inventing one.
        parts.append(f"| summarize Events=count() by Operation | top {limit} by Events desc")
    kql = " ".join(parts)

    try:
        rows = await client.query(kql, n.timespan(hours))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not rows:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=f"No Microsoft 365 activity matched in the last {hours:g}h",
                recommended_action=RecommendedAction(
                    summary="Call again without `operation` to see which operations "
                    "actually occur in this window.",
                ),
            )
        ]
    if not operation:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"{r.get('Operation')} — {r.get('Events')} events ({hours:g}h)",
                evidence=[
                    Evidence(key="operation", value=str(r.get("Operation"))),
                    Evidence(key="events", value=str(r.get("Events"))),
                ],
                recommended_action=RecommendedAction(
                    summary=f"Call search_office_activity with "
                    f"operation=\"{r.get('Operation')}\" to see the events.",
                ),
            )
            for r in rows[:limit]
        ]
    return _rows_to_findings(rows, "Operation", limit)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/tests/ -v && uv run mypy .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add servers/sentinel-mcp/
git commit -m "feat(sentinel): search_office_activity with one-call operation discovery"
```

---

### Task 9: `list_sentinel_incidents`

**Files:**
- Modify: `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`, `servers/sentinel-mcp/tests/test_tools.py`

**Interfaces:**
- Produces: `tools.list_sentinel_incidents(client, severity_min: str = "low", status: str = "any", hours: float = 168, limit: int = 25) -> list[Finding]`

- [ ] **Step 1: Write the failing tests**

Append to `servers/sentinel-mcp/tests/test_tools.py`:

```python
SI = "SecurityIncident"
_INC = [{
    "IncidentNumber": 4211, "Title": "Exfiltration incident", "Severity": "High",
    "Status": "New", "Owner": "", "Tactics": '["Exfiltration"]',
    "TimeGenerated": "2026-08-10T12:00:00Z", "IncidentUrl": "https://portal.azure.com/x",
}]


async def test_list_sentinel_incidents_returns_incident_findings(fake):
    client = fake(rows={USAGE: _TABLES, SI: _INC})
    out = await tools.list_sentinel_incidents(client)
    assert any(f.finding_type.value == "incident" for f in out)
    assert any("Exfiltration incident" in f.title for f in out)


async def test_list_sentinel_incidents_surfaces_mitre_tactics(fake):
    # Tactics are what this view adds over f0-defender.list_incidents.
    client = fake(rows={USAGE: _TABLES, SI: _INC})
    out = await tools.list_sentinel_incidents(client)
    ev = {e.key: e.value for f in out for e in f.evidence}
    assert "tactics" in ev and "Exfiltration" in ev["tactics"]


async def test_list_sentinel_incidents_severity_min_filters(fake):
    client = fake(rows={USAGE: _TABLES, SI: []})
    await tools.list_sentinel_incidents(client, severity_min="high")
    kql = [q for q in client.queries if SI in q][0]
    assert "High" in kql and "Informational" not in kql


async def test_list_sentinel_incidents_status_filter(fake):
    client = fake(rows={USAGE: _TABLES, SI: []})
    await tools.list_sentinel_incidents(client, status="new")
    kql = [q for q in client.queries if SI in q][0]
    assert 'Status =~ "New"' in kql


async def test_list_sentinel_incidents_status_any_emits_no_status_filter(fake):
    client = fake(rows={USAGE: _TABLES, SI: []})
    await tools.list_sentinel_incidents(client, status="any")
    kql = [q for q in client.queries if SI in q][0]
    assert "Status =~" not in kql


async def test_list_sentinel_incidents_deduplicates_by_incident_number(fake):
    # SecurityIncident appends a NEW ROW on every incident update, so a naive
    # list shows the same incident many times.
    client = fake(rows={USAGE: _TABLES, SI: []})
    await tools.list_sentinel_incidents(client)
    kql = [q for q in client.queries if SI in q][0]
    assert "arg_max(TimeGenerated, *) by IncidentNumber" in kql


async def test_list_sentinel_incidents_bad_severity_reports(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.list_sentinel_incidents(client, severity_min="catastrophic")
    assert len(out) == 1 and out[0].finding_type.value == "posture"


async def test_list_sentinel_incidents_missing_table_returns_posture(fake):
    client = fake(rows={USAGE: [{"DataType": "Syslog", "GB": 1.0}]})
    out = await tools.list_sentinel_incidents(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_tools.py -k sentinel_incidents -v`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Implement**

Append to `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`:

```python
_SEV_ORDER = ("informational", "low", "medium", "high")
_SEV_VALUE = {
    "informational": "Informational", "low": "Low", "medium": "Medium", "high": "High",
}
_SEV_FINDING = {
    "informational": Severity.info, "low": Severity.low,
    "medium": Severity.medium, "high": Severity.high,
}
_STATUS_VALUE = {"new": "New", "active": "Active", "closed": "Closed"}


async def list_sentinel_incidents(
    client: Any,
    severity_min: str = "low",
    status: str = "any",
    hours: float = 168,
    limit: int = 25,
) -> list[Finding]:
    """The Sentinel SOC incident queue, with MITRE tactics."""
    cap = "Sentinel incidents"
    if severity_min not in _SEV_ORDER:
        return [_bad_arg("severity_min", severity_min, ", ".join(_SEV_ORDER))]
    if status != "any" and status not in _STATUS_VALUE:
        return [_bad_arg("status", status, "new, active, closed, any")]

    missing = await require_table(client, "SecurityIncident", "Sentinel incidents")
    if missing:
        return [missing]

    hours = n.clamp_hours(hours, client.retention_days)
    limit = clamp_limit(limit)
    wanted = _SEV_ORDER[_SEV_ORDER.index(severity_min):]
    sev_list = ", ".join(f'"{_SEV_VALUE[s]}"' for s in wanted)

    parts = [
        "SecurityIncident",
        f"| where TimeGenerated > ago({hours:g}h)",
        # SecurityIncident appends a row per update; collapse to the latest
        # state per incident or the queue reads as duplicates.
        "| summarize arg_max(TimeGenerated, *) by IncidentNumber",
        f"| where Severity in~ ({sev_list})",
    ]
    if status != "any":
        parts.append(f'| where Status =~ "{_STATUS_VALUE[status]}"')
    parts.append("| order by TimeGenerated desc")
    parts.append(f"| take {limit}")
    kql = " ".join(parts)

    try:
        rows = await client.query(kql, n.timespan(hours))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not rows:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"No Sentinel incidents at severity {severity_min}+ in the last {hours:g}h",
            )
        ]

    out: list[Finding] = []
    for r in rows[:limit]:
        num = str(r.get("IncidentNumber", "?"))
        out.append(
            Finding(
                source="sentinel",
                finding_type=FindingType.incident,
                severity=_SEV_FINDING.get(str(r.get("Severity", "")).lower(), Severity.medium),
                title=f"#{num}: {r.get('Title') or 'Sentinel incident'}",
                entity=Entity(kind=EntityKind.tenant, id=num, name=str(r.get("Title") or "")),
                evidence=[
                    Evidence(key="status", value=str(r.get("Status") or "")),
                    Evidence(key="severity", value=str(r.get("Severity") or "")),
                    Evidence(key="tactics", value=str(r.get("Tactics") or "")),
                    Evidence(key="owner", value=str(r.get("Owner") or "unassigned")),
                ],
                observed_at=str(r.get("TimeGenerated") or "") or None,
            )
        )
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/tests/ -v && uv run mypy .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add servers/sentinel-mcp/
git commit -m "feat(sentinel): list_sentinel_incidents with tactics and per-incident dedup"
```

---

### Task 10: `get_detection_coverage`

**Files:**
- Modify: `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`, `servers/sentinel-mcp/tests/test_tools.py`

**Interfaces:**
- Produces: `tools.get_detection_coverage(client) -> list[Finding]`

- [ ] **Step 1: Write the failing tests**

Append to `servers/sentinel-mcp/tests/test_tools.py`:

```python
_RULES = [
    {"kind": "Scheduled", "properties": {"displayName": "Disabling Security Services",
     "enabled": True, "severity": "Medium", "tactics": ["DefenseEvasion"]}},
    {"kind": "Fusion", "properties": {"displayName": "Advanced Multistage Attack Detection",
     "enabled": True, "severity": "High", "tactics": ["InitialAccess", "Exfiltration"]}},
    {"kind": "Scheduled", "properties": {"displayName": "Retired rule",
     "enabled": False, "severity": "Low", "tactics": []}},
]


async def test_get_detection_coverage_summarizes_rules(fake):
    client = fake(arm={"alertRules": _RULES})
    out = await tools.get_detection_coverage(client)
    summary = out[0]
    ev = {e.key: e.value for e in summary.evidence}
    assert ev["rules_total"] == "3"
    assert ev["rules_enabled"] == "2"


async def test_get_detection_coverage_names_uncovered_tactics(fake):
    # Naming the GAP is the whole value: the incident queue cannot show it.
    client = fake(arm={"alertRules": _RULES})
    out = await tools.get_detection_coverage(client)
    text = " ".join(f.title + str(f.evidence) for f in out)
    assert "Persistence" in text or "uncovered" in text.lower()


async def test_get_detection_coverage_without_arm_config_returns_posture(fake):
    client = fake(has_arm=False)
    out = await tools.get_detection_coverage(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert "SENTINEL_SUBSCRIPTION_ID" in (
        out[0].recommended_action.summary if out[0].recommended_action else ""
    )


async def test_get_detection_coverage_403_names_sentinel_reader(fake):
    client = fake(raise_on={"alertRules": GraphError(403, "forbidden")})
    out = await tools.get_detection_coverage(client)
    assert len(out) == 1
    assert "Microsoft Sentinel Reader" in (
        out[0].recommended_action.summary if out[0].recommended_action else ""
    )


async def test_get_detection_coverage_no_rules_is_a_finding_not_silence(fake):
    client = fake(arm={"alertRules": []})
    out = await tools.get_detection_coverage(client)
    assert len(out) >= 1
    assert "0" in out[0].title or "no" in out[0].title.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_tools.py -k detection_coverage -v`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Implement**

Append to `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`:

```python
# The MITRE tactics Sentinel analytics rules can carry. Used to name the GAP —
# a rule inventory without the uncovered set is just a count.
_ALL_TACTICS = (
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact",
)


async def get_detection_coverage(client: Any) -> list[Finding]:
    """Analytics-rule inventory and MITRE tactic gaps (Sentinel management API)."""
    cap = "Sentinel detection coverage"
    if not client.has_arm:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title="Sentinel detection coverage unavailable — ARM coordinates not configured",
                recommended_action=RecommendedAction(
                    summary="Set SENTINEL_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP and "
                    "SENTINEL_WORKSPACE_NAME in .env.sentinel, and grant the app the "
                    "'Microsoft Sentinel Reader' role.",
                    confidence="high",
                ),
            )
        ]

    try:
        rules = await client.arm_list("alertRules")
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="arm")
        if mapped:
            return [mapped]
        raise

    enabled = [r for r in rules if (r.get("properties") or {}).get("enabled")]
    kinds: dict[str, int] = {}
    covered: set[str] = set()
    for r in rules:
        kinds[str(r.get("kind", "unknown"))] = kinds.get(str(r.get("kind", "unknown")), 0) + 1
        for t in (r.get("properties") or {}).get("tactics") or []:
            covered.add(str(t))
    uncovered = [t for t in _ALL_TACTICS if t not in covered]

    summary = Finding(
        source="sentinel",
        finding_type=FindingType.posture,
        severity=Severity.medium if len(enabled) < 10 else Severity.info,
        title=f"{len(rules)} Sentinel analytics rules ({len(enabled)} enabled), "
        f"{len(covered)} of {len(_ALL_TACTICS)} MITRE tactics covered",
        entity=Entity(kind=EntityKind.tenant, id="sentinel"),
        evidence=[
            Evidence(key="rules_total", value=str(len(rules))),
            Evidence(key="rules_enabled", value=str(len(enabled))),
            Evidence(key="kinds", value=", ".join(f"{k}={v}" for k, v in sorted(kinds.items()))),
            Evidence(key="tactics_covered", value=", ".join(sorted(covered)) or "none"),
            Evidence(key="tactics_uncovered", value=", ".join(uncovered) or "none"),
        ],
        recommended_action=RecommendedAction(
            summary="Uncovered tactics: " + (", ".join(uncovered) or "none") +
            ". Add analytics rules or enable Content Hub solutions for these.",
            confidence="medium",
        ),
    )

    out = [summary]
    for r in enabled[:25]:
        p = r.get("properties") or {}
        out.append(
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Rule: {p.get('displayName') or 'unnamed'}",
                entity=Entity(kind=EntityKind.rule, id=str(r.get("name") or "")),
                evidence=[
                    Evidence(key="kind", value=str(r.get("kind") or "")),
                    Evidence(key="severity", value=str(p.get("severity") or "")),
                    Evidence(key="tactics", value=", ".join(str(t) for t in (p.get("tactics") or []))),
                ],
            )
        )
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/tests/ -v && uv run mypy .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add servers/sentinel-mcp/
git commit -m "feat(sentinel): get_detection_coverage naming uncovered MITRE tactics"
```

---

### Task 11: `run_kql` escape hatch

**Files:**
- Modify: `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`, `servers/sentinel-mcp/tests/test_tools.py`

**Interfaces:**
- Produces: `tools.run_kql(client, kql: str, hours: float = 24, limit: int = 25) -> list[Finding]`

- [ ] **Step 1: Write the failing tests**

Append to `servers/sentinel-mcp/tests/test_tools.py`:

```python
async def test_run_kql_passes_query_through(fake):
    client = fake(rows={"Heartbeat": [{"Computer": "srv-1"}]})
    out = await tools.run_kql(client, "Heartbeat | project Computer")
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_run_kql_appends_bound_when_query_has_none(fake):
    client = fake(rows={"Heartbeat": []})
    await tools.run_kql(client, "Heartbeat | project Computer", limit=10)
    assert "| take 10" in client.queries[0]


async def test_run_kql_respects_an_existing_bound(fake):
    client = fake(rows={"Heartbeat": []})
    await tools.run_kql(client, "Heartbeat | take 5")
    assert client.queries[0].count("take") == 1


async def test_run_kql_rejects_control_commands(fake):
    client = fake(rows={})
    for bad in (".create table X", ".drop table X", ".set-or-append Y", ".ingest inline"):
        out = await tools.run_kql(client, bad)
        assert len(out) == 1 and out[0].finding_type.value == "posture", bad
    assert client.queries == []


async def test_run_kql_rejects_empty_query(fake):
    client = fake(rows={})
    out = await tools.run_kql(client, "   ")
    assert len(out) == 1 and out[0].finding_type.value == "posture"


async def test_run_kql_semantic_error_returns_reason(fake):
    client = fake(raise_on={"Bogus": GraphError(400, "SemanticError: Failed to resolve 'Nope'")})
    out = await tools.run_kql(client, "Bogus | project Nope")
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert "Nope" in out[0].title
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_tools.py -k run_kql -v`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Implement**

Append to `servers/sentinel-mcp/f0_sentinel_mcp/tools.py`:

```python
# Kusto control commands start with a dot and can mutate the workspace
# (.create, .drop, .set-or-append, .ingest). This server is read-only, so they
# never reach the API.
_CONTROL_PREFIX = "."


async def run_kql(client: Any, kql: str, hours: float = 24, limit: int = 25) -> list[Finding]:
    """Run a caller-supplied read-only KQL query, force-bounded."""
    cap = "Sentinel KQL query"
    query = (kql or "").strip()
    if not query:
        return [_bad_arg("kql", kql or "", "a KQL query, e.g. 'Heartbeat | take 10'")]
    if query.startswith(_CONTROL_PREFIX):
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title="Kusto control commands are not permitted — this server is read-only",
                recommended_action=RecommendedAction(
                    summary="Use a tabular query (TableName | where ... | take N).",
                    confidence="high",
                ),
            )
        ]

    hours = n.clamp_hours(hours, client.retention_days)
    limit = clamp_limit(limit)
    lowered = query.lower()
    if " take " not in lowered and " limit " not in lowered and not lowered.endswith("take"):
        query = f"{query} | take {limit}"

    try:
        rows = await client.query(query, n.timespan(hours))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not rows:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=f"Query returned no rows in the last {hours:g}h",
            )
        ]
    first_col = next(iter(rows[0].keys()), "result")
    return _rows_to_findings(rows, first_col, limit)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/tests/ -v && uv run mypy . && uv run ruff check servers/sentinel-mcp`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add servers/sentinel-mcp/
git commit -m "feat(sentinel): run_kql escape hatch, read-only validated and force-bounded"
```

---

### Task 12: `server.py` — registration and the redaction boundary

**Files:**
- Create: `servers/sentinel-mcp/f0_sentinel_mcp/server.py`, `servers/sentinel-mcp/tests/test_server.py`

**Interfaces:**
- Consumes: every tool from Tasks 5–11.
- Produces: module-level `mcp` (an `MCPServer` named `f0-sentinel`) with 7 registered tools, and `main()`.

**Tool docstrings carry the routing contract.** They are written for a model, not a human: one sentence on when to use, one on what it returns, and an explicit pointer at the neighbouring server where a collision exists.

- [ ] **Step 1: Write the failing tests**

`servers/sentinel-mcp/tests/test_server.py`:

```python
"""Server-registration contract: tool count, names, and routing docstrings."""
from __future__ import annotations

from f0_sentinel_mcp import server

EXPECTED = {
    "list_data_sources", "hunt_firewall", "hunt_dns_web", "search_office_activity",
    "list_sentinel_incidents", "get_detection_coverage", "run_kql",
}


async def _tools():
    return {t.name: t for t in await server.mcp.list_tools()}


async def test_registers_exactly_the_seven_tools():
    assert set(await _tools()) == EXPECTED


async def test_no_tool_name_collides_with_another_server():
    # f0-defender already owns list_incidents and run_hunting_query.
    names = set(await _tools())
    assert "list_incidents" not in names
    assert "run_hunting_query" not in names


async def test_arguments_are_flat_scalars_only():
    for name, t in (await _tools()).items():
        for arg, spec in (t.input_schema or {}).get("properties", {}).items():
            assert spec.get("type") != "object", f"{name}.{arg} is a nested object"
            assert spec.get("type") != "array", f"{name}.{arg} is an array"


async def test_routing_docstrings_name_the_neighbouring_tool():
    tools = await _tools()
    assert "hunt_dns_web" in (tools["hunt_firewall"].description or "")
    assert "run_hunting_query" in (tools["run_kql"].description or "")
    assert "list_incidents" in (tools["list_sentinel_incidents"].description or "")
    assert "search_audit_log" in (tools["search_office_activity"].description or "")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/sentinel-mcp/tests/test_server.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'f0_sentinel_mcp.server'`

- [ ] **Step 3: Implement**

`servers/sentinel-mcp/f0_sentinel_mcp/server.py`:

```python
"""Sentinel MCP server (stdio). Read-only tools over Microsoft Sentinel.

Loads credentials from the SENTINEL_* environment (typically `.env.sentinel`),
opens a short-lived client per call, maps results to findings, and redacts every
payload before returning it to the agent.
"""
from __future__ import annotations

from typing import Any, Literal

from dotenv import load_dotenv
from f0_sectools_core.auth.config import SentinelConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server import MCPServer

from . import tools
from .client import SentinelClient

load_dotenv(".env.sentinel")

mcp = MCPServer("f0-sentinel")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    return [redact_obj(f.model_dump()) for f in findings]


def _client() -> SentinelClient:
    return SentinelClient(SentinelConfig.from_env("SENTINEL"))


@mcp.tool()
async def list_data_sources() -> list[dict[str, Any]]:
    """List which security telemetry this Sentinel workspace actually ingests.

    Start here when you do not know what data exists — every workspace is
    different. Returns each table with data in the last 30 days and a family
    label (firewall, dns_web, office, identity, incident, custom). Use it to
    pick which hunt tool can answer a question before you call one."""
    async with _client() as c:
        return _render(await tools.list_data_sources(c))


@mcp.tool()
async def hunt_firewall(
    action: Literal["allowed", "blocked", "detected", "any"] = "any",
    indicator: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """SEARCH firewall traffic (Check Point / Fortinet) for an IP or port.

    Use for questions about network connections, blocked traffic, or a
    suspicious IP talking through the perimeter. `indicator` must be an IP
    ADDRESS or PORT NUMBER — this table carries almost no URLs or usernames, so
    a domain here finds nothing: for domains, URLs and web categories use
    hunt_dns_web instead. Without an indicator this returns an aggregate
    (top talkers by action), not individual events."""
    async with _client() as c:
        return _render(await tools.hunt_firewall(c, action, indicator, hours, limit))


@mcp.tool()
async def hunt_dns_web(
    surface: Literal["dns", "web", "vpn"] = "dns",
    action: Literal["allowed", "blocked", "detected", "any"] = "any",
    indicator: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """SEARCH DNS, web-proxy, or remote-access VPN activity (Cisco Umbrella).

    Choose surface by what you are looking for: dns — a domain was resolved or
    blocked (C2, newly-registered domains, blocked categories); web — a URL was
    fetched, a file downloaded, or a proxy verdict applied; vpn — remote-access
    VPN sessions and failures. `indicator` is a domain, URL fragment or IP.
    Without an indicator this returns an aggregate, not individual events. For
    perimeter firewall connections by IP/port use hunt_firewall."""
    async with _client() as c:
        return _render(await tools.hunt_dns_web(c, surface, action, indicator, hours, limit))


@mcp.tool()
async def search_office_activity(
    workload: Literal["sharepoint", "onedrive", "exchange", "teams", "any"] = "any",
    operation: str = "",
    user: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Search Microsoft 365 audit activity: who accessed, downloaded, or shared what.

    Answers "who downloaded X", "who read that mailbox", "what did this user do
    in SharePoint". Call it FIRST without `operation` to get the list of
    operations that actually occurred, then again with an exact operation name
    (e.g. FileDownloaded, MailItemsAccessed, FileAccessed). This is the fast
    path for M365 audit — prefer it over f0-purview's search_audit_log, which
    submits an asynchronous query that takes 5-15 minutes to return."""
    async with _client() as c:
        return _render(
            await tools.search_office_activity(c, workload, operation, user, hours, limit)
        )


@mcp.tool()
async def list_sentinel_incidents(
    severity_min: Literal["informational", "low", "medium", "high"] = "low",
    status: Literal["new", "active", "closed", "any"] = "any",
    hours: float = 168,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """List the Sentinel SOC incident queue with MITRE tactics, status and owner.

    Use when asked about the SOC queue, incident workload, unassigned incidents,
    or which ATT&CK tactics are showing up. This is the Sentinel-side view; for
    the Defender XDR-native incident view (with its own alert and device
    context) use f0-defender's list_incidents. Not an alert list — for
    individual alerts use f0-defender's list_alerts."""
    async with _client() as c:
        return _render(await tools.list_sentinel_incidents(c, severity_min, status, hours, limit))


@mcp.tool()
async def get_detection_coverage() -> list[dict[str, Any]]:
    """Report Sentinel's analytics-rule inventory and which MITRE tactics are UNCOVERED.

    Answers "what do we actually detect?", "where are our detection gaps?",
    "how many analytics rules are enabled?". Returns rule counts by kind, the
    enabled/disabled split, and the named list of ATT&CK tactics no rule covers.
    Requires the ARM coordinates in .env.sentinel; without them it says so."""
    async with _client() as c:
        return _render(await tools.get_detection_coverage(c))


@mcp.tool()
async def run_kql(kql: str, hours: float = 24, limit: int = 25) -> list[dict[str, Any]]:
    """Run a CUSTOM read-only KQL query against the Sentinel Log Analytics workspace.

    Use only when no guided tool fits — prefer hunt_firewall, hunt_dns_web,
    search_office_activity or list_sentinel_incidents, which build correct KQL
    for you. Call list_data_sources first to learn which tables exist in this
    workspace. This queries the SENTINEL workspace; for Microsoft Defender
    device/email advanced-hunting tables use f0-defender's run_hunting_query
    instead. The query is force-bounded if it carries no `take`."""
    async with _client() as c:
        return _render(await tools.run_kql(c, kql, hours, limit))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/sentinel-mcp/ -v && uv run mypy . && uv run ruff check servers/sentinel-mcp`
Expected: PASS

> If `mcp.server.MCPServer` or `t.input_schema` do not resolve, match whatever `servers/purview-mcp/f0_purview_mcp/server.py` and `integrations/test_integrations_valid.py` currently use — the repo migrated to MCP 2.0 in PR #94 and those two files are the reference.

- [ ] **Step 5: Commit**

```bash
git add servers/sentinel-mcp/
git commit -m "feat(sentinel): register 7 tools with routing docstrings and redaction boundary"
```

---

### Task 13: Evals — coverage plus routing tasks

**Files:**
- Create: `evals/sentinel/tasks.yaml`
- Modify: `evals/test_eval_coverage.py`, `evals/run.py`

**Interfaces:**
- Consumes: the 7 registered tool names (Task 12).
- Produces: an eval task set that `test_eval_coverage.py` accepts (every tool referenced, no unknown tools).

- [ ] **Step 1: Write the task set**

`evals/sentinel/tasks.yaml`:

```yaml
# Small-model tool-calling eval task set — Sentinel server.
# See evals/defender/tasks.yaml for the field schema. evals/test_eval_coverage.py
# enforces that every Sentinel tool has at least one task.
#
# The final block is ROUTING tasks: this server deliberately sits next to
# f0-defender and f0-purview, and the risk it adds is misrouting, not a missing
# capability. Those tasks must be run against TWO models — one model is not a
# control (see the eval-findings notes on the hunt/logon misroute).

- prompt: "What security data do we actually collect in Sentinel?"
  expect_tool: list_data_sources

- prompt: "Which log sources are feeding our SIEM?"
  expect_tool: list_data_sources

- prompt: "Show me traffic the firewall blocked in the last 12 hours."
  expect_tool: hunt_firewall
  expect_args_contains: { action: blocked }

- prompt: "Did anything connect to 203.0.113.45 through the firewall?"
  expect_tool: hunt_firewall
  expect_args_contains: { indicator: "203.0.113.45" }

- prompt: "Has anyone on the network resolved the domain evil-c2.com?"
  expect_tool: hunt_dns_web
  expect_args_contains: { indicator: "evil-c2.com" }

- prompt: "What web categories are getting blocked by the proxy?"
  expect_tool: hunt_dns_web
  expect_args_contains: { surface: web }

- prompt: "Show me remote access VPN sessions from the last day."
  expect_tool: hunt_dns_web
  expect_args_contains: { surface: vpn }

- prompt: "Who downloaded files from OneDrive yesterday?"
  expect_tool: search_office_activity
  expect_args_contains: { workload: onedrive }

- prompt: "Did anyone access mailboxes they shouldn't have in Exchange?"
  expect_tool: search_office_activity

- prompt: "What's in the Sentinel incident queue right now?"
  expect_tool: list_sentinel_incidents

- prompt: "Show me high severity Sentinel incidents that are still open."
  expect_tool: list_sentinel_incidents
  expect_args_contains: { severity_min: high }

- prompt: "What attacks do our Sentinel analytics rules actually detect?"
  expect_tool: get_detection_coverage

- prompt: "Where are the gaps in our detection coverage?"
  expect_tool: get_detection_coverage

- prompt: "Run this Sentinel query for me: Heartbeat | summarize count() by Computer"
  expect_tool: run_kql

# --- routing tasks: the three deliberate adjacencies ---

- prompt: "Search the firewall logs for connections to the domain badsite.io"
  expect_tool: hunt_dns_web    # NOT hunt_firewall: the CEF table has no URLs

- prompt: "Which MITRE tactics are showing up in our Sentinel SOC queue?"
  expect_tool: list_sentinel_incidents

- prompt: "Query the Sentinel workspace for the Syslog table."
  expect_tool: run_kql
```

- [ ] **Step 2: Register the server**

In `evals/test_eval_coverage.py`, add to `SERVERS`:

```python
    ("sentinel", "f0_sentinel_mcp.server"),
```

In `evals/run.py`, add to `SERVER_MODULES`:

```python
    "sentinel": "f0_sentinel_mcp.server",
```

- [ ] **Step 3: Run the coverage test**

Run: `uv run pytest evals/test_eval_coverage.py -v`
Expected: PASS — in particular `test_eval_coverage_matches_registered_tools[sentinel-...]`, which fails if any tool lacks a task or a task names an unknown tool.

- [ ] **Step 4: Commit**

```bash
git add evals/
git commit -m "test(sentinel): eval task set with routing tasks for the three adjacencies"
```

---

### Task 14: Reciprocal routing edits + regenerate docs

**Files:**
- Modify: `servers/defender-mcp/f0_defender_mcp/server.py` (docstrings only), `servers/purview-mcp/f0_purview_mcp/server.py` (docstrings only), `docs/reference/` (regenerated)

**Interfaces:**
- Consumes: the tool names registered in Task 12.
- Produces: no code change — description text only. **No behaviour change to either live-validated server.**

- [ ] **Step 1: Add the pointer to purview's audit search**

In `servers/purview-mcp/f0_purview_mcp/server.py`, in `search_audit_log`'s docstring, insert after the first paragraph:

```
    If a Sentinel workspace is configured, prefer f0-sentinel's
    search_office_activity for SharePoint / OneDrive / Exchange / Teams file and
    mail activity: it queries the same audit data through Log Analytics and
    returns in under a second, where this tool's asynchronous search takes 5-15
    minutes. Use this tool when there is no Sentinel workspace, or for audit
    records that predate the workspace's retention.
```

- [ ] **Step 2: Add the pointer to defender's incident list**

In `servers/defender-mcp/f0_defender_mcp/server.py`, in `list_incidents`'s docstring, append:

```
    For the Sentinel SOC queue view of the same incidents — with MITRE tactics,
    SOC status and owner — use f0-sentinel's list_sentinel_incidents.
```

- [ ] **Step 3: Add the pointer to defender's hunting query**

In `servers/defender-mcp/f0_defender_mcp/server.py`, in `run_hunting_query`'s docstring, append:

```
    This is Defender advanced hunting (device, email and identity tables), not
    Sentinel workspace KQL. For firewall, DNS, syslog or other Log Analytics
    tables use f0-sentinel's run_kql.
```

- [ ] **Step 4: Verify no behaviour changed**

Run: `uv run pytest servers/defender-mcp servers/purview-mcp -v`
Expected: PASS, unchanged — these are description-only edits.

- [ ] **Step 5: Regenerate the reference docs**

Run: `uv run python scripts/gen_docs.py && uv run pytest scripts/tests/test_gen_docs.py -v`
Expected: `docs/reference/` updated with the sentinel server and the amended descriptions; drift guard PASS.

- [ ] **Step 6: Commit**

```bash
git add servers/defender-mcp servers/purview-mcp docs/reference/
git commit -m "docs(routing): two-way pointers between sentinel, defender and purview tools"
```

---

### Task 15: Smoke script and live validation

**Files:**
- Create: `scripts/live_smoke_sentinel.py`

**Interfaces:**
- Consumes: every tool (Tasks 5–11), `SentinelClient` (Task 2).
- Produces: a runnable script printing redacted findings per tool.

> **This task calls a LIVE security platform.** CLAUDE.md requires explicit user confirmation before running it, and network/sandbox access must be enabled. Do not run it autonomously.

- [ ] **Step 1: Write the smoke script**

`scripts/live_smoke_sentinel.py`:

```python
"""Live smoke test for the Sentinel MCP server against a real workspace.

Usage (from the repo root):
    1. Copy servers/sentinel-mcp/.env.sentinel.example to ./.env.sentinel and fill it in.
    2. uv run python scripts/live_smoke_sentinel.py [--persona hunter]

Calls each read tool against live Sentinel and prints REDACTED findings. Secrets
are never printed. Auth / permission / rate-limit issues show up as posture
findings (graceful degradation), not crashes.
"""
from __future__ import annotations

import argparse
import asyncio
import json

from dotenv import load_dotenv
from f0_sectools_core.auth.config import SentinelConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sentinel_mcp import tools
from f0_sentinel_mcp.client import SentinelClient

load_dotenv(".env.sentinel")


def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:6]:
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 6:
        print(f"... ({len(findings) - 6} more)")


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=float, default=24.0)
    args = parser.parse_args()

    async with SentinelClient(SentinelConfig.from_env("SENTINEL")) as c:
        _show("list_data_sources", await tools.list_data_sources(c))
        _show("hunt_firewall (aggregate)", await tools.hunt_firewall(c, action="blocked", hours=args.hours))
        _show("hunt_dns_web dns (aggregate)", await tools.hunt_dns_web(c, surface="dns", action="blocked", hours=args.hours))
        _show("hunt_dns_web web", await tools.hunt_dns_web(c, surface="web", action="blocked", hours=args.hours))
        _show("hunt_dns_web vpn", await tools.hunt_dns_web(c, surface="vpn", hours=args.hours))
        _show("search_office_activity (discovery)", await tools.search_office_activity(c, hours=args.hours))
        _show("search_office_activity FileDownloaded", await tools.search_office_activity(c, operation="FileDownloaded", hours=args.hours))
        _show("list_sentinel_incidents", await tools.list_sentinel_incidents(c, hours=168))
        _show("get_detection_coverage", await tools.get_detection_coverage(c))
        _show("run_kql", await tools.run_kql(c, "Heartbeat | summarize n=count() by Computer", hours=args.hours))


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: Ask the user for permission to run it**

Do not proceed without an explicit "yes". State that it queries the live workspace read-only.

- [ ] **Step 3: Run the smoke test**

Run: `uv run python scripts/live_smoke_sentinel.py`

- [ ] **Step 4: Fix forward on the known-uncertain items**

Recipe step 9 always surfaces 1–3 mismatches. These three are *known* unknowns — check each explicitly:

1. **`Usage` completeness.** Confirm `list_data_sources` returns `OfficeActivity`, `SecurityIncident` and `SecurityAlert`. A billable-only roll-up omits them; the probe deliberately does not filter `IsBillable`, but verify. **If `Usage` still under-reports, switch `probe._USAGE_KQL` to the workspace metadata endpoint** (`GET /v1/workspaces/{id}/metadata`, which lists tables authoritatively) and update the probe docstring to say why.
2. **`vpn` action values.** `SURFACE_SPECS["vpn"].action_map` guesses `connected`/`failed` for `Event_Type_s`. Confirm with `Cisco_Umbrella_ravpnlogs_CL | summarize count() by Event_Type_s` and correct the map.
3. **`OfficeActivity` column names.** Confirm `UserId`, `ClientIP`, `OfficeObjectId` and `ResultStatus` exist; adjust `_OA_PROJECT` if not.

Also confirm `list_sentinel_incidents` shows each incident once (the `arg_max` dedup working), and that `get_detection_coverage` returns rules rather than a 403.

- [ ] **Step 5: Update the contract tests to match reality**

Any field name corrected above must be corrected in `tests/test_tools.py` too, so the fake data keeps encoding the real shape.

- [ ] **Step 6: Run the full suite and commit**

```bash
uv run pytest && uv run ruff check . && uv run mypy .
git add scripts/live_smoke_sentinel.py servers/sentinel-mcp/
git commit -m "test(sentinel): live smoke script and field-name corrections from live validation"
```

---

### Task 16: Skills

**Files:**
- Create: `skills/sentinel/data-source-coverage/SKILL.md`, `skills/sentinel/network-investigation/SKILL.md`, `skills/sentinel/detection-coverage/SKILL.md`

**Interfaces:**
- Consumes: tool **base names** (no runtime prefix): `list_data_sources`, `hunt_firewall`, `hunt_dns_web`, `search_office_activity`, `list_sentinel_incidents`, `get_detection_coverage`, `run_kql`.
- Produces: three agentskills.io skill packages. **`description` must be ≤ 60 characters** — `skills/test_skills_valid.py` enforces it.

- [ ] **Step 1: Write `skills/sentinel/data-source-coverage/SKILL.md`**

```markdown
---
name: data-source-coverage
description: Audit what telemetry Sentinel ingests and what is missing
version: 0.1.0
---

# Sentinel Data-Source Coverage

## When to Use

When asked "what are we collecting?", "is our SIEM seeing the firewall?",
"where are our visibility gaps?", or before any Sentinel hunt when you do not
yet know which tables exist. Every workspace ingests a different set — never
assume a table is present.

## Procedure

1. Call `list_data_sources`. It returns each table ingesting in the last 30
   days with a family label.
2. Group by family and state coverage plainly: which of firewall, dns_web,
   office, identity and incident are present, and which are absent.
3. Call `get_detection_coverage` to add the detection side — ingesting data
   with no analytics rules is collection, not detection.
4. Report gaps as gaps. A missing family is a finding, not an omission.

## Pitfalls

- **A table ingesting is not a table that is useful.** Check volume and whether
  the fields you need are populated before promising an answer from it.
- **Do not use the connector list as a coverage answer.** AMA/DCR and codeless
  connectors do not register there; `list_data_sources` reads actual ingest.
- **Absence is a real answer.** If `hunt_firewall` reports no CEF data, say the
  workspace has no firewall feed — do not report "no malicious traffic found".

## Verification

Coverage claims must trace to a `list_data_sources` row. If you cannot name the
table, do not claim the visibility.
```

- [ ] **Step 2: Write `skills/sentinel/network-investigation/SKILL.md`**

```markdown
---
name: network-investigation
description: Hunt an indicator across firewall, DNS and web telemetry
version: 0.1.0
---

# Sentinel Network Investigation

## When to Use

When investigating an indicator — a domain, URL, IP or port — against
perimeter and egress telemetry: "did anyone reach this C2?", "what did the
firewall block from this host?", "is anyone using a personal VPN?". This is the
network complement to endpoint investigation.

## Procedure

1. If you do not know what telemetry exists, call `list_data_sources` first.
2. Route the indicator by TYPE — this matters more than anything else here:
   - **Domain or URL** → `hunt_dns_web` (`surface="dns"` for resolutions,
     `surface="web"` for fetches and downloads).
   - **IP address or port** → `hunt_firewall`.
   - A domain passed to `hunt_firewall` finds nothing: that table carries
     almost no URLs.
3. Start with `action="blocked"` to see what controls already caught, then
   `action="allowed"` to find what got through. What was allowed is usually the
   more urgent half.
4. For a user rather than an address, use `surface="vpn"` for remote-access
   sessions, or `search_office_activity` for what they touched in M365.
5. Correlate: a blocked DNS request plus an allowed firewall session to the
   same infrastructure means the DNS control worked and the IP path did not.

## Pitfalls

- **Without an indicator these tools return aggregates, not events.** That is
  deliberate — the firewall table is very large. Supply an indicator to see
  individual rows.
- **`hours` is capped at the workspace retention.** Asking for 90 days on a
  30-day workspace silently means 30; do not present it as 90.
- **Umbrella categories are a JSON list in one field.** Treat category matches
  as substring matches, not exact ones.
- Firewall data is Sentinel-only. For endpoint process/network telemetry use
  the Defender or LimaCharlie tools instead.

## Verification

Every claim names the tool, the indicator, and the window. If a tool returned a
posture finding saying the table is absent, report that — never substitute a
different data source silently.
```

- [ ] **Step 3: Write `skills/sentinel/detection-coverage/SKILL.md`**

```markdown
---
name: detection-coverage
description: Review Sentinel analytics rules and MITRE tactic gaps
version: 0.1.0
---

# Sentinel Detection Coverage

## When to Use

For the detection-engineer question: "what do we actually detect?", "which
ATT&CK tactics have no rule?", "are our analytics rules enabled?". Also when a
CISO asks whether the SIEM is doing detection or just collection.

## Procedure

1. Call `get_detection_coverage`. Read three things: rule count, the
   enabled/disabled split, and the named uncovered tactics.
2. Call `list_sentinel_incidents` and compare. A large incident volume against
   a small rule count means the incidents come from a connected product
   (Defender XDR) rather than from Sentinel analytics — that is a real and
   commonly-missed finding, and it is invisible from the queue alone.
3. Call `list_data_sources`. A tactic can only be covered where the telemetry
   exists: an uncovered tactic with no supporting table is a data gap, not a
   rule gap, and the remediation is different.
4. Report rule gaps and data gaps separately, then name the highest-value
   additions.

## Pitfalls

- **A disabled rule is not coverage.** Count only enabled rules.
- **Do not equate incident volume with detection quality.** Mirrored incidents
  inflate the count without any local detection engineering.
- If the ARM coordinates are unset, the tool says so — report that as missing
  configuration, not as zero rules.

## Verification

Every coverage or gap claim traces to a `get_detection_coverage` evidence
field. Uncovered tactics are quoted from `tactics_uncovered`, never inferred.
```

- [ ] **Step 4: Validate the skills**

Run: `uv run pytest skills/test_skills_valid.py -v`
Expected: PASS — frontmatter valid, every `description` ≤ 60 chars.

- [ ] **Step 5: Commit**

```bash
git add skills/sentinel/
git commit -m "feat(sentinel): three portable skills (coverage, network hunt, detection gaps)"
```

---

### Task 17: Docs, runtime wiring, and final verification

**Files:**
- Create: `servers/sentinel-mcp/README.md`
- Modify: `CLAUDE.md`, `README.md`, `docs/user-guide/README.md`, `integrations/pi/mcp.json`, `integrations/hermes/config.example.yaml`, `integrations/hermes/distribution/config.yaml`, `opencode.json`, `.opencode/skills/`, `docs/reference/` (regenerated)

- [ ] **Step 1: Write the server README**

Follow `servers/_TEMPLATE.md` exactly. It must document: the two API surfaces and their two Azure roles; every env var including the optional ARM triple and `SENTINEL_RETENTION_DAYS`; all 7 tools with arguments; the non-goals from the spec (no device hunt, no UEBA, no classification, no connector list, no sign-in tool) with the one-line reason each; and the `hours`-capped-at-retention behaviour.

- [ ] **Step 2: Update `CLAUDE.md`**

- Architecture tree: add `sentinel-mcp/  # built + live-validated` under `servers/`.
- Platform Integrations table: add the row

  `| Microsoft Sentinel | SIEM | Entra app | KQL telemetry (firewall, DNS/web, M365 audit), incidents, analytics rules | — |`

  and remove the now-superseded planned-`sentinel` mention from the "planned" comment in the tree.
- Skills paragraph: add `sentinel/` to the `skills/` listing.

- [ ] **Step 3: Update the top-level `README.md` and user guide**

Add the server to the status list in `README.md` and to the support matrix in `docs/user-guide/README.md`.

- [ ] **Step 4: Wire every runtime**

- `integrations/pi/mcp.json` — add the `f0-sentinel` server entry using the placeholder path `/ABSOLUTE/PATH/TO/sec-tools`.
- `integrations/hermes/config.example.yaml` — add to `mcp_servers`.
- `integrations/hermes/distribution/config.yaml` — add to `mcp_servers`.
- `opencode.json` — add the server with a relative command, matching the existing eight entries.
- `.opencode/skills/` — add three symlinks pointing at `skills/sentinel/*`, matching the existing symlink style.

- [ ] **Step 5: Run the drift guards**

Run: `uv run pytest integrations/test_integrations_valid.py -v`
Expected: PASS — this test fails if any runtime template is missing the new server.

- [ ] **Step 6: Regenerate the reference docs**

Run: `uv run python scripts/gen_docs.py`
Expected: `docs/reference/tools/` gains the sentinel page; `docs/reference/skills.md` grows to 30 skills.

- [ ] **Step 7: Full verification**

Run each and confirm the output before claiming completion:

```bash
uv run pytest
uv run ruff check .
uv run mypy .
git status --short          # confirm no .env.* staged
```

Expected: all green; `git status` shows only intended files.

- [ ] **Step 8: Commit**

```bash
git add servers/sentinel-mcp/README.md CLAUDE.md README.md docs/ integrations/ opencode.json .opencode/
git commit -m "docs(sentinel): server README, platform table, runtime wiring and regenerated reference"
```

- [ ] **Step 9: Report and stop**

Report the commit hashes and the test counts. **Do not push** — wait for explicit instruction (CLAUDE.md).

---

## Post-Plan: deferred to a follow-up

Out of scope here, recorded so they are not lost:

- **Scorecard re-run.** Tool count moves 51 → 58. Re-run the eval scorecard across the model matrix and compare against the pre-Sentinel baseline, as was done when Tenable was added. Routing tasks must run on two models.
- **Gated write actions.** Incident close / classify / assign through `core/gating/` — deliberately excluded from v1.
- **Multi-workspace support.** Only if a deployment needs it; it introduces a workspace argument, which is a small-model hazard.
- **Deferred surfaces:** `OracleDB_*_CL` business-app logs, `Syslog`, `ThreatIntelIndicators`.
