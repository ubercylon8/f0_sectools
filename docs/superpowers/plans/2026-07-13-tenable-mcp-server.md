# tenable-mcp Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `tenable-mcp`, the sixth f0_sectools platform server — a thin, read-only MCP server over Tenable Vulnerability Management (Workbenches API) exposing 6 flat findings-returning tools, plus 3 skills.

**Architecture:** Thin server over shared `core/`, mirroring `projectachilles-mcp` exactly (static-key REST, async `httpx`, one `get(path, params)` helper, tools → `list[Finding]`, platform errors → graceful findings). Auth is `X-ApiKeys: accessKey=<>;secretKey=<>`. `core/` is unchanged except one `TenableConfig` dataclass.

**Tech Stack:** Python 3.11+, `mcp` (FastMCP), `httpx`, `pytest`/`pytest-asyncio`, `uv` workspace. Lint `ruff`, type-check `mypy` (strict, shipped source only).

## Global Constraints

- **Read-only. No gated writes, no `core/gating` wiring.** Config has no `allow_write`.
- **No `core/` changes beyond adding `TenableConfig`** to `core/f0_sectools_core/auth/config.py` (+ its test).
- **Redact at the server boundary:** every returned finding via `redact_obj(f.model_dump())`. Never in tools.
- **Every platform failure becomes a `Finding`, never an exception** reaching the model — via `map_tenable_error`.
- **`source="tenable"`** on every finding.
- **Flat args only.** `severity_min` is the closed enum `low | medium | high | critical` wherever it appears. Bounded `limit` defaults. No nested/object args.
- **Tool docstrings are platform-anchored** (start "Tenable …") to avoid cross-server description collisions (the #2.5 pattern).
- **Tenable severity is integer `0–4`** = info/low/medium/high/critical.
- **Response field names are assumed and live-validated** (recipe step 9). Contract tests use mocks that match the code's assumed shapes; live validation fix-forwards mismatches. This is expected, not a defect.
- **Base URL default:** `https://cloud.tenable.com`.
- **Commits:** conventional, with the repo's `Co-Authored-By:` + `Claude-Session:` trailers. **Never push** — surface the hash.
- Spec: `docs/superpowers/specs/2026-07-13-tenable-mcp-server-design.md`. Branch: `feat/tenable-mcp-server` (spec committed as `6ef1299`).

## File Structure

```
core/f0_sectools_core/auth/config.py     # + TenableConfig                 (Task 1)
core/tests/test_config.py                # + 3 TenableConfig tests          (Task 1)
servers/tenable-mcp/
  pyproject.toml                         # package metadata                 (Task 2)
  README.md                              # scopes + tool list               (Task 2)
  .env.tenable.example                   # required env vars                (Task 2)
  f0_tenable_mcp/__init__.py             # empty package marker             (Task 2)
  f0_tenable_mcp/client.py               # TenableClient + TenableError     (Task 3)
  f0_tenable_mcp/errors.py               # map_tenable_error                (Task 3)
  f0_tenable_mcp/tools.py                # 6 read tools + helpers      (Tasks 4-5)
  f0_tenable_mcp/server.py               # FastMCP, redact at boundary      (Task 6)
  tests/test_tools.py                    # contract tests (fake client)(Tasks 3-5)
evals/tenable/tasks.yaml                 # >=1 task per tool                (Task 7)
evals/run.py                             # + "tenable" in SERVER_MODULES    (Task 7)
evals/test_eval_coverage.py             # + "tenable" in SERVERS           (Task 7)
scripts/live_smoke_tenable.py            # live smoke + --persona           (Task 8)
skills/tenable/exposure-posture-review/SKILL.md      # default focus        (Task 9)
skills/tenable/host-vulnerability-triage/SKILL.md                           (Task 9)
skills/tenable/scan-coverage-review/SKILL.md                                (Task 9)
CLAUDE.md, README.md, docs/user-guide/README.md      # docs                (Task 10)
```

---

### Task 1: TenableConfig + test

**Files:**
- Modify: `core/f0_sectools_core/auth/config.py` (add `TenableConfig` after `ProjectAchillesConfig`)
- Test: `core/tests/test_config.py` (add 3 tests + import)

**Interfaces:**
- Produces: `TenableConfig(access_key: str, secret_key: str, base_url: str = "https://cloud.tenable.com", verify_tls: bool = True)` with `@classmethod from_env(prefix="TENABLE", env=None) -> TenableConfig`.

- [ ] **Step 1: Write the failing tests**

Add to `core/tests/test_config.py` (import `TenableConfig` from `f0_sectools_core.auth.config` alongside the existing imports):

```python
def test_tenable_config_loads():
    env = {
        "TENABLE_ACCESS_KEY": "ak-123",
        "TENABLE_SECRET_KEY": "sk-456",
    }
    cfg = TenableConfig.from_env(env=env)
    assert cfg.access_key == "ak-123"
    assert cfg.secret_key == "sk-456"
    assert cfg.base_url == "https://cloud.tenable.com"  # default
    assert cfg.verify_tls is True


def test_tenable_config_missing_raises():
    with pytest.raises(ValueError, match="TENABLE_SECRET_KEY"):
        TenableConfig.from_env(env={"TENABLE_ACCESS_KEY": "ak-123"})


def test_tenable_config_custom_base_url_strips_slash():
    env = {
        "TENABLE_ACCESS_KEY": "ak-123",
        "TENABLE_SECRET_KEY": "sk-456",
        "TENABLE_BASE_URL": "https://cloud.tenable.eu/",
        "TENABLE_VERIFY_TLS": "false",
    }
    cfg = TenableConfig.from_env(env=env)
    assert cfg.base_url == "https://cloud.tenable.eu"
    assert cfg.verify_tls is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest core/tests/test_config.py -k tenable -v`
Expected: FAIL — `ImportError: cannot import name 'TenableConfig'`.

- [ ] **Step 3: Implement `TenableConfig`**

Add after `ProjectAchillesConfig` in `core/f0_sectools_core/auth/config.py` (match the existing `@dataclass` decoration style used on the other config classes in that file):

```python
@dataclass
class TenableConfig:
    """Tenable Vulnerability Management credentials: an access key + secret key.

    Sent as ``X-ApiKeys: accessKey=<>;secretKey=<>``. Read-only server, so there
    is no allow_write flag. Loaded from .env.tenable. Secrets never leave this
    layer or get logged.
    """

    access_key: str
    secret_key: str
    base_url: str = "https://cloud.tenable.com"
    verify_tls: bool = True

    @classmethod
    def from_env(
        cls, prefix: str = "TENABLE", env: Mapping[str, str] | None = None
    ) -> TenableConfig:
        env = env if env is not None else os.environ
        required = {
            "access_key": f"{prefix}_ACCESS_KEY",
            "secret_key": f"{prefix}_SECRET_KEY",
        }
        missing = [name for name in required.values() if not env.get(name)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
        verify = env.get(f"{prefix}_VERIFY_TLS", "true").strip().lower() in _TRUE
        base_url = env.get(f"{prefix}_BASE_URL", "https://cloud.tenable.com").rstrip("/")
        return cls(
            access_key=env[required["access_key"]],
            secret_key=env[required["secret_key"]],
            base_url=base_url,
            verify_tls=verify,
        )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest core/tests/test_config.py -k tenable -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/auth/config.py core/tests/test_config.py
git commit -m "feat(tenable): add TenableConfig (X-ApiKeys, read-only)"
```

---

### Task 2: Scaffold the server package

**Files:**
- Create: `servers/tenable-mcp/pyproject.toml`, `servers/tenable-mcp/README.md`, `servers/tenable-mcp/.env.tenable.example`, `servers/tenable-mcp/f0_tenable_mcp/__init__.py`, `servers/tenable-mcp/tests/__init__.py`

**Interfaces:**
- Produces: importable package `f0_tenable_mcp`; console script `f0-tenable-mcp`.

- [ ] **Step 1: Create `servers/tenable-mcp/pyproject.toml`**

```toml
[project]
name = "f0-tenable-mcp"
version = "0.0.1"
description = "f0_sectools MCP server for Tenable Vulnerability Management (read-only) — vulnerabilities, assets, scans."
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
f0-tenable-mcp = "f0_tenable_mcp.server:main"

[tool.uv.sources]
f0-sectools-core = { workspace = true }

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["f0_tenable_mcp"]
```

- [ ] **Step 2: Create `servers/tenable-mcp/.env.tenable.example`**

```bash
# Tenable Vulnerability Management API keys (My Account -> API Keys -> Generate).
# The user account's role gates what the read tools can see; a read-only/Basic
# role with "Can View" on the relevant assets is sufficient.
TENABLE_ACCESS_KEY=
TENABLE_SECRET_KEY=

# Optional. Default is the US cloud. Use https://cloud.tenable.eu for the EU region.
# TENABLE_BASE_URL=https://cloud.tenable.com
# TENABLE_VERIFY_TLS=true
```

- [ ] **Step 3: Create `servers/tenable-mcp/README.md`**

```markdown
# f0-tenable-mcp

Read-only MCP server over **Tenable Vulnerability Management** (Workbenches API).
Part of [f0_sectools](../../README.md). Returns the normalized findings schema
through the shared `core/` redaction layer.

## Credentials

Copy `.env.tenable.example` to `./.env.tenable` (repo root) and fill in a Tenable
**access key** and **secret key** (Tenable UI → *My Account → API Keys → Generate*).
Sent as `X-ApiKeys: accessKey=<>;secretKey=<>`. Secrets are never logged or returned.

A read-only Tenable role is sufficient. `.env.tenable` is gitignored.

## Tools (all read-only)

| Tool | What it returns |
|---|---|
| `get_vulnerability_summary` | Environment-wide vulnerability counts by severity |
| `list_top_vulnerabilities` | Worst plugins/CVEs by severity + VPR (fix-first) |
| `list_assets` | Asset inventory (filter by hostname / severity) |
| `get_asset_vulnerabilities` | Vulnerabilities on one host (hostname/ip/UUID) |
| `get_vulnerability_info` | One plugin: CVSS/VPR, description, remediation |
| `list_scans` | Scan inventory + last-run freshness |

## Run

```bash
uv run f0-tenable-mcp   # stdio server; Ctrl-C to stop
```
```

- [ ] **Step 4: Create the package markers**

`servers/tenable-mcp/f0_tenable_mcp/__init__.py`:
```python
"""f0_sectools MCP server for Tenable Vulnerability Management (read-only)."""
```

`servers/tenable-mcp/tests/__init__.py`:
```python
```

- [ ] **Step 5: Sync the workspace**

Run: `uv sync --all-packages`
Expected: resolves and installs `f0-tenable-mcp` (editable) with no errors.

- [ ] **Step 6: Commit**

```bash
git add servers/tenable-mcp/pyproject.toml servers/tenable-mcp/README.md servers/tenable-mcp/.env.tenable.example servers/tenable-mcp/f0_tenable_mcp/__init__.py servers/tenable-mcp/tests/__init__.py
git commit -m "feat(tenable): scaffold tenable-mcp server package"
```

---

### Task 3: Client + error mapping

**Files:**
- Create: `servers/tenable-mcp/f0_tenable_mcp/client.py`, `servers/tenable-mcp/f0_tenable_mcp/errors.py`
- Test: `servers/tenable-mcp/tests/test_tools.py` (create; error-mapping tests + `FakeClient`)

**Interfaces:**
- Produces:
  - `TenableError(status: int, message: str)` (message redacted).
  - `TenableClient(config: TenableConfig)` with `async get(path: str, params: dict | None = None) -> dict`, and `__aenter__`/`__aexit__`.
  - `map_tenable_error(e: Exception, capability: str) -> Finding | None` (None → caller re-raises).
  - `FakeClient` test helper (canned responses by path prefix; configured raises).

- [ ] **Step 1: Write the failing tests**

Create `servers/tenable-mcp/tests/test_tools.py`:

```python
"""Contract tests for the Tenable tools.

Tools take a thin async client; tests pass a fake client (no HTTP / network).
Real Tenable field names are validated by the live smoke test (recipe step 9).
"""
from __future__ import annotations

import pytest
from f0_tenable_mcp import tools
from f0_tenable_mcp.client import TenableError
from f0_tenable_mcp.errors import map_tenable_error


class FakeClient:
    """Fake async client: canned responses by path prefix, or a configured error."""

    def __init__(self, responses=None, raise_on=None):
        self._responses = responses or {}
        self._raise = raise_on or {}
        self.calls: list[tuple[str, dict]] = []

    async def get(self, path, params=None):
        self.calls.append((path, params or {}))
        for p, err in self._raise.items():
            if path.startswith(p):
                raise err
        for p, resp in self._responses.items():
            if path.startswith(p):
                return resp
        return {}


def test_map_tenable_error_403_permission():
    f = map_tenable_error(TenableError(403, "forbidden"), "Tenable vulnerabilities")
    assert f is not None
    assert f.finding_type.value == "posture"
    assert "Tenable vulnerabilities" in f.title


def test_map_tenable_error_429_rate_limited():
    f = map_tenable_error(TenableError(429, "slow down"), "Tenable assets")
    assert f is not None and "Rate limited" in f.title


def test_map_tenable_error_502_unavailable():
    f = map_tenable_error(TenableError(503, "bad gateway"), "Tenable scans")
    assert f is not None and "unavailable" in f.title.lower()


def test_map_tenable_error_unknown_returns_none():
    assert map_tenable_error(ValueError("nope"), "x") is None
    assert map_tenable_error(TenableError(418, "teapot"), "x") is None


def test_tenable_error_redacts_message():
    e = TenableError(401, "key=SECRETVALUE invalid")
    assert "SECRETVALUE" not in str(e) or "REDACTED" in str(e)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest servers/tenable-mcp/tests/test_tools.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_tenable_mcp.tools'` (and `.client`, `.errors`).

- [ ] **Step 3: Implement `client.py`**

`servers/tenable-mcp/f0_tenable_mcp/client.py`:
```python
"""Thin async client for the Tenable Vulnerability Management API.

Auth is a static ``X-ApiKeys: accessKey=<>;secretKey=<>`` header. Errors are
raised as TenableError with a redacted message; the tools map them to graceful
findings.
"""
from __future__ import annotations

from typing import Any

import httpx
from f0_sectools_core.auth.config import TenableConfig
from f0_sectools_core.redaction.redact import redact_text


class TenableError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = redact_text(message)
        super().__init__(f"Tenable HTTP {status}: {self.message}")


class TenableClient:
    def __init__(self, config: TenableConfig) -> None:
        self.base_url = config.base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            verify=config.verify_tls,
            timeout=60.0,
            headers={
                "X-ApiKeys": f"accessKey={config.access_key};secretKey={config.secret_key}",
                "Accept": "application/json",
            },
        )

    async def __aenter__(self) -> TenableClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = await self._client.get(f"{self.base_url}{path}", params=params)
        if resp.status_code // 100 != 2:
            try:
                body = resp.json()
                msg = body.get("error") or body.get("message") or resp.text
            except Exception:
                msg = resp.text
            raise TenableError(resp.status_code, str(msg) or "request failed")
        return resp.json() if resp.content else {}
```

- [ ] **Step 4: Implement `errors.py`**

`servers/tenable-mcp/f0_tenable_mcp/errors.py`:
```python
"""Map Tenable HTTP errors to graceful findings."""
from __future__ import annotations

from f0_sectools_core.schema.findings import (
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from .client import TenableError


def map_tenable_error(e: Exception, capability: str) -> Finding | None:
    """Return a graceful finding for known Tenable errors, else None (caller re-raises)."""
    if not isinstance(e, TenableError):
        return None
    if e.status == 401:
        return Finding(
            source="tenable",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Tenable authentication failed — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary="Check TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY "
                "(valid, non-revoked API keys).",
                confidence="high",
            ),
        )
    if e.status == 403:
        return Finding.permission_missing(
            "tenable", "a read-scope Tenable role", capability
        )
    if e.status == 429:
        return Finding.rate_limited("tenable", capability)
    if e.status in (502, 503, 504):
        return Finding.api_unavailable("tenable", capability, e.status)
    return None
```

- [ ] **Step 5: Create a minimal `tools.py` stub so the test module imports**

`servers/tenable-mcp/f0_tenable_mcp/tools.py` (helpers now; tools land in Tasks 4–5):
```python
"""Tenable Vulnerability Management read tools -> findings.

Read-only. Each tool catches a TenableError (auth / permission / rate-limit /
gateway) and returns a graceful finding instead of crashing. Response field
names are validated by the live smoke test (recipe step 9).
"""
from __future__ import annotations

import re
from typing import Any

from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Reference,
    Severity,
)

from .errors import map_tenable_error

# Tenable severity integer 0-4 -> our Severity.
_SEV_BY_INT = {
    0: Severity.info,
    1: Severity.low,
    2: Severity.medium,
    3: Severity.high,
    4: Severity.critical,
}
# severity_min enum string -> the minimum Tenable integer to include.
_SEV_MIN = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _sev(value: Any) -> Severity:
    """Tenable severity (int 0-4, or a name) -> Severity; unknown -> info."""
    if isinstance(value, int):
        return _SEV_BY_INT.get(value, Severity.info)
    return {s.value: s for s in Severity}.get(str(value).lower(), Severity.info)


def _rows(resp: Any, key: str) -> list[dict[str, Any]]:
    """Extract a list of rows: a bare array, or ``{key: [...]}``."""
    if isinstance(resp, list):
        return resp
    if isinstance(resp, dict):
        got = resp.get(key)
        if isinstance(got, list):
            return got
    return []
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest servers/tenable-mcp/tests/test_tools.py -v`
Expected: PASS (5 passed) — error mapping + redaction verified.

- [ ] **Step 7: Commit**

```bash
git add servers/tenable-mcp/f0_tenable_mcp/client.py servers/tenable-mcp/f0_tenable_mcp/errors.py servers/tenable-mcp/f0_tenable_mcp/tools.py servers/tenable-mcp/tests/test_tools.py
git commit -m "feat(tenable): client (X-ApiKeys) + error mapping + tool helpers"
```

---

### Task 4: Posture & prioritization tools

Adds `get_vulnerability_summary`, `list_top_vulnerabilities`, `list_assets` to `tools.py`.

**Files:**
- Modify: `servers/tenable-mcp/f0_tenable_mcp/tools.py`
- Test: `servers/tenable-mcp/tests/test_tools.py`

**Interfaces:**
- Consumes: `map_tenable_error`, `_sev`, `_rows`, `_SEV_MIN` (Task 3).
- Produces:
  - `async get_vulnerability_summary(tio: Any) -> list[Finding]`
  - `async list_top_vulnerabilities(tio: Any, severity_min: str = "high", limit: int = 10) -> list[Finding]`
  - `async list_assets(tio: Any, hostname: str = "", severity_min: str = "", limit: int = 25) -> list[Finding]`

- [ ] **Step 1: Write the failing tests**

Append to `servers/tenable-mcp/tests/test_tools.py` (`TenableError` is already imported from Task 3):

```python
_VULNS = {"vulnerabilities": [
    {"plugin_id": 19506, "plugin_name": "SSL cert", "severity": 4, "count": 12, "vpr_score": 9.1,
     "cves": ["CVE-2021-1234"]},
    {"plugin_id": 11219, "plugin_name": "Open port", "severity": 1, "count": 40, "vpr_score": 2.0},
]}


@pytest.mark.asyncio
async def test_get_vulnerability_summary_counts_by_severity():
    tio = FakeClient(responses={"/workbenches/vulnerabilities": _VULNS})
    findings = await tools.get_vulnerability_summary(tio)
    f = findings[0]
    assert f.finding_type.value == "posture"
    assert f.severity.value == "critical"  # worst present (sev 4)
    # evidence carries per-severity instance counts
    ev = {e.key: e.value for e in f.evidence}
    assert ev["critical"] == "12" and ev["low"] == "40"


@pytest.mark.asyncio
async def test_list_top_vulnerabilities_filters_and_sorts():
    tio = FakeClient(responses={"/workbenches/vulnerabilities": _VULNS})
    findings = await tools.list_top_vulnerabilities(tio, severity_min="high", limit=10)
    # only the critical plugin passes severity_min=high; low one is filtered out
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert findings[0].references[0].id == "CVE-2021-1234"
    assert any(e.key == "affected_hosts" for e in findings[0].evidence)


@pytest.mark.asyncio
async def test_list_assets_maps_host_entities():
    tio = FakeClient(responses={"/workbenches/assets": {"assets": [
        {"id": "abc", "fqdn": ["web-01.corp"], "ipv4": ["10.0.0.5"], "last_seen": "2026-07-01T00:00:00Z"},
    ]}})
    findings = await tools.list_assets(tio, limit=5)
    assert findings[0].entity.kind.value == "host"
    assert findings[0].entity.name == "web-01.corp"


@pytest.mark.asyncio
async def test_list_top_vulnerabilities_permission_error_is_graceful():
    tio = FakeClient(raise_on={"/workbenches/vulnerabilities": TenableError(403, "forbidden")})
    findings = await tools.list_top_vulnerabilities(tio)
    assert len(findings) == 1 and findings[0].finding_type.value == "posture"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest servers/tenable-mcp/tests/test_tools.py -k "summary or top_vulnerabilities or list_assets" -v`
Expected: FAIL — `AttributeError: module 'f0_tenable_mcp.tools' has no attribute 'get_vulnerability_summary'`.

- [ ] **Step 3: Implement the three tools**

Append to `servers/tenable-mcp/f0_tenable_mcp/tools.py`:

```python
def _cves(row: dict[str, Any]) -> list[Reference]:
    out: list[Reference] = []
    for cve in row.get("cves") or row.get("cve") or []:
        out.append(Reference(type="cve", id=str(cve)))
    pid = row.get("plugin_id")
    if pid is not None:
        out.append(Reference(type="tenable_plugin", id=str(pid)))
    return out


async def get_vulnerability_summary(tio: Any) -> list[Finding]:
    try:
        d = await tio.get("/workbenches/vulnerabilities")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable vulnerability summary")
        if finding:
            return [finding]
        raise
    counts = {s: 0 for s in Severity}
    for row in _rows(d, "vulnerabilities"):
        counts[_sev(row.get("severity"))] += int(row.get("count", 0) or 0)
    worst = next(
        (s for s in (Severity.critical, Severity.high, Severity.medium, Severity.low)
         if counts[s] > 0),
        Severity.info,
    )
    evidence = [Evidence(key=s.value, value=str(counts[s]))
                for s in (Severity.critical, Severity.high, Severity.medium,
                          Severity.low, Severity.info)]
    total = sum(counts.values())
    return [
        Finding(
            source="tenable",
            finding_type=FindingType.posture,
            severity=worst,
            title=f"Tenable vulnerability posture: {total} findings across the environment",
            entity=Entity(kind=EntityKind.tenant, id="tenable"),
            evidence=evidence,
            recommended_action=RecommendedAction(
                summary="Prioritize the critical/high vulnerabilities; see "
                "list_top_vulnerabilities for the fix-first list.",
            ),
        )
    ]


async def list_top_vulnerabilities(
    tio: Any, severity_min: str = "high", limit: int = 10
) -> list[Finding]:
    try:
        d = await tio.get("/workbenches/vulnerabilities")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable top vulnerabilities")
        if finding:
            return [finding]
        raise
    floor = _SEV_MIN.get(severity_min, 3)
    rows = [r for r in _rows(d, "vulnerabilities")
            if int(r.get("severity", 0) or 0) >= floor]
    rows.sort(
        key=lambda r: (int(r.get("severity", 0) or 0), float(r.get("vpr_score", 0) or 0)),
        reverse=True,
    )
    out: list[Finding] = []
    for r in rows[:limit]:
        evidence = [Evidence(key="affected_hosts", value=str(r.get("count", 0)))]
        if r.get("vpr_score") is not None:
            evidence.append(Evidence(key="vpr", value=str(r.get("vpr_score"))))
        out.append(
            Finding(
                source="tenable",
                finding_type=FindingType.misconfig,
                severity=_sev(r.get("severity")),
                title=f"Tenable: {r.get('plugin_name', 'vulnerability')} "
                f"(plugin {r.get('plugin_id', '?')})",
                entity=Entity(kind=EntityKind.rule, id=str(r.get("plugin_id", "?")),
                              name=r.get("plugin_name")),
                evidence=evidence,
                references=_cves(r),
                recommended_action=RecommendedAction(
                    summary="Review affected hosts and remediate; see "
                    "get_vulnerability_info for the fix.",
                ),
            )
        )
    return out


async def list_assets(
    tio: Any, hostname: str = "", severity_min: str = "", limit: int = 25
) -> list[Finding]:
    try:
        d = await tio.get("/workbenches/assets", params={"limit": limit} if limit else None)
    except Exception as e:
        finding = map_tenable_error(e, "Tenable assets")
        if finding:
            return [finding]
        raise
    out: list[Finding] = []
    for a in _rows(d, "assets")[:limit]:
        fqdns = a.get("fqdn") or []
        ipv4s = a.get("ipv4") or []
        name = (fqdns[0] if fqdns else (ipv4s[0] if ipv4s else a.get("id", "asset")))
        if hostname and hostname.lower() not in str(name).lower():
            continue
        evidence = []
        if a.get("last_seen"):
            evidence.append(Evidence(key="last_seen", value=str(a["last_seen"])))
        if ipv4s:
            evidence.append(Evidence(key="ipv4", value=str(ipv4s[0])))
        out.append(
            Finding(
                source="tenable",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Tenable asset: {name}",
                entity=Entity(kind=EntityKind.host, id=str(a.get("id", name)), name=str(name)),
                evidence=evidence,
                observed_at=a.get("last_seen"),
            )
        )
    return out
```

> Note: `severity_min` on `list_assets` is accepted for interface symmetry with the
> other tools; asset-level severity filtering is applied at live validation once the
> real per-asset severity field is confirmed. Leaving the arg wired keeps the tool
> signature stable. (Do not add speculative filtering on an unconfirmed field.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest servers/tenable-mcp/tests/test_tools.py -k "summary or top_vulnerabilities or list_assets" -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add servers/tenable-mcp/f0_tenable_mcp/tools.py servers/tenable-mcp/tests/test_tools.py
git commit -m "feat(tenable): posture + prioritization tools (summary, top-vulns, assets)"
```

---

### Task 5: Per-asset, detail & scan tools

Adds `get_asset_vulnerabilities` (with UUID-or-hostname resolution), `get_vulnerability_info`, `list_scans`.

**Files:**
- Modify: `servers/tenable-mcp/f0_tenable_mcp/tools.py`
- Test: `servers/tenable-mcp/tests/test_tools.py`

**Interfaces:**
- Consumes: `_rows`, `_sev`, `_cves`, `_UUID_RE`, `map_tenable_error` (Tasks 3–4).
- Produces:
  - `async _resolve_asset_uuid(tio: Any, asset: str) -> str | None`
  - `async get_asset_vulnerabilities(tio: Any, asset: str, severity_min: str = "high", limit: int = 25) -> list[Finding]`
  - `async get_vulnerability_info(tio: Any, plugin_id: str) -> list[Finding]`
  - `async list_scans(tio: Any, limit: int = 25) -> list[Finding]`

- [ ] **Step 1: Write the failing tests**

Append to `servers/tenable-mcp/tests/test_tools.py`:

```python
_UUID = "12345678-1234-1234-1234-1234567890ab"


@pytest.mark.asyncio
async def test_get_asset_vulnerabilities_uuid_direct():
    tio = FakeClient(responses={
        f"/workbenches/assets/{_UUID}/vulnerabilities": {"vulnerabilities": [
            {"plugin_id": 19506, "plugin_name": "SSL cert", "severity": 4, "count": 1,
             "cves": ["CVE-2021-1234"]},
        ]},
    })
    findings = await tools.get_asset_vulnerabilities(tio, _UUID)
    assert findings[0].entity.kind.value == "host"
    assert findings[0].severity.value == "critical"
    # went straight to the uuid endpoint, no asset search
    assert any(_UUID in c[0] for c in tio.calls)


@pytest.mark.asyncio
async def test_get_asset_vulnerabilities_resolves_hostname():
    tio = FakeClient(responses={
        "/workbenches/assets": {"assets": [
            {"id": _UUID, "fqdn": ["web-01.corp"], "ipv4": ["10.0.0.5"]}]},
        f"/workbenches/assets/{_UUID}/vulnerabilities": {"vulnerabilities": [
            {"plugin_id": 11219, "plugin_name": "x", "severity": 3, "count": 2}]},
    })
    findings = await tools.get_asset_vulnerabilities(tio, "web-01", severity_min="high")
    assert findings and findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_get_asset_vulnerabilities_no_match_is_graceful():
    tio = FakeClient(responses={"/workbenches/assets": {"assets": []}})
    findings = await tools.get_asset_vulnerabilities(tio, "ghost-host")
    assert len(findings) == 1
    assert findings[0].finding_type.value == "posture"
    assert "ghost-host" in findings[0].title


@pytest.mark.asyncio
async def test_get_vulnerability_info_maps_detail():
    tio = FakeClient(responses={"/workbenches/vulnerabilities/19506/info": {"info": {
        "plugin_details": {"name": "SSL cert", "severity": 4},
        "description": "the desc", "solution": "patch it",
        "cvss_base_score": "7.5", "vpr": {"score": 9.1}, "cve": ["CVE-2021-1234"]}}})
    findings = await tools.get_vulnerability_info(tio, "19506")
    f = findings[0]
    assert f.finding_type.value == "misconfig"
    assert any("patch it" in e.value for e in f.evidence)
    assert f.references[0].id == "CVE-2021-1234"


@pytest.mark.asyncio
async def test_list_scans_maps_status():
    tio = FakeClient(responses={"/scans": {"scans": [
        {"id": 7, "name": "Weekly", "status": "completed",
         "last_modification_date": 1783900000}]}})
    findings = await tools.list_scans(tio, limit=5)
    assert findings[0].title.startswith("Tenable scan")
    assert any(e.key == "status" for e in findings[0].evidence)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest servers/tenable-mcp/tests/test_tools.py -k "asset_vulnerabilities or vulnerability_info or list_scans" -v`
Expected: FAIL — attributes `get_asset_vulnerabilities`, `get_vulnerability_info`, `list_scans` missing.

- [ ] **Step 3: Implement the three tools + resolver**

Append to `servers/tenable-mcp/f0_tenable_mcp/tools.py`:

```python
async def _resolve_asset_uuid(tio: Any, asset: str) -> str | None:
    """A UUID passes through; else match the first asset whose fqdn/ipv4 contains `asset`."""
    if _UUID_RE.match(asset):
        return asset
    d = await tio.get("/workbenches/assets")
    needle = asset.lower()
    for a in _rows(d, "assets"):
        hay = " ".join(str(x).lower() for x in
                       (a.get("fqdn") or []) + (a.get("ipv4") or []) + [a.get("id", "")])
        if needle in hay:
            return str(a.get("id"))
    return None


async def get_asset_vulnerabilities(
    tio: Any, asset: str, severity_min: str = "high", limit: int = 25
) -> list[Finding]:
    try:
        uuid = await _resolve_asset_uuid(tio, asset)
        if uuid is None:
            return [Finding(
                source="tenable",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Tenable: no asset matches '{asset}'",
                recommended_action=RecommendedAction(
                    summary="Check the hostname/IP, or list_assets to find the exact name.",
                ),
            )]
        d = await tio.get(f"/workbenches/assets/{uuid}/vulnerabilities")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable asset vulnerabilities")
        if finding:
            return [finding]
        raise
    floor = _SEV_MIN.get(severity_min, 3)
    rows = [r for r in _rows(d, "vulnerabilities")
            if int(r.get("severity", 0) or 0) >= floor]
    rows.sort(key=lambda r: int(r.get("severity", 0) or 0), reverse=True)
    out: list[Finding] = []
    for r in rows[:limit]:
        out.append(
            Finding(
                source="tenable",
                finding_type=FindingType.misconfig,
                severity=_sev(r.get("severity")),
                title=f"Tenable: {r.get('plugin_name', 'vulnerability')} on {asset}",
                entity=Entity(kind=EntityKind.host, id=str(uuid), name=asset),
                evidence=[Evidence(key="instances", value=str(r.get("count", 0)))],
                references=_cves(r),
            )
        )
    return out


async def get_vulnerability_info(tio: Any, plugin_id: str) -> list[Finding]:
    try:
        d = await tio.get(f"/workbenches/vulnerabilities/{plugin_id}/info")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable vulnerability detail")
        if finding:
            return [finding]
        raise
    info = d.get("info", {}) if isinstance(d, dict) else {}
    details = info.get("plugin_details", {})
    name = details.get("name", f"plugin {plugin_id}")
    evidence = []
    if info.get("description"):
        evidence.append(Evidence(key="description", value=str(info["description"])[:500]))
    if info.get("solution"):
        evidence.append(Evidence(key="solution", value=str(info["solution"])[:500]))
    if info.get("cvss_base_score"):
        evidence.append(Evidence(key="cvss", value=str(info["cvss_base_score"])))
    vpr = info.get("vpr") or {}
    if isinstance(vpr, dict) and vpr.get("score") is not None:
        evidence.append(Evidence(key="vpr", value=str(vpr["score"])))
    refs = [Reference(type="cve", id=str(c)) for c in info.get("cve") or []]
    refs.append(Reference(type="tenable_plugin", id=str(plugin_id)))
    return [
        Finding(
            source="tenable",
            finding_type=FindingType.misconfig,
            severity=_sev(details.get("severity")),
            title=f"Tenable plugin {plugin_id}: {name}",
            entity=Entity(kind=EntityKind.rule, id=str(plugin_id), name=name),
            evidence=evidence,
            references=refs,
            recommended_action=RecommendedAction(
                summary="Apply the solution above to the affected assets.",
            ),
        )
    ]


async def list_scans(tio: Any, limit: int = 25) -> list[Finding]:
    try:
        d = await tio.get("/scans")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable scans")
        if finding:
            return [finding]
        raise
    out: list[Finding] = []
    for s in _rows(d, "scans")[:limit]:
        evidence = [Evidence(key="status", value=str(s.get("status", "unknown")))]
        if s.get("last_modification_date"):
            evidence.append(
                Evidence(key="last_run", value=str(s.get("last_modification_date"))))
        out.append(
            Finding(
                source="tenable",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Tenable scan: {s.get('name', s.get('id', 'scan'))}",
                entity=Entity(kind=EntityKind.rule, id=str(s.get("id", "?")),
                              name=s.get("name")),
                evidence=evidence,
            )
        )
    return out
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest servers/tenable-mcp/tests/test_tools.py -v`
Expected: PASS (all tests — Task 3, 4, 5 tests green together).

- [ ] **Step 5: Commit**

```bash
git add servers/tenable-mcp/f0_tenable_mcp/tools.py servers/tenable-mcp/tests/test_tools.py
git commit -m "feat(tenable): per-asset vulns (uuid/hostname), plugin detail, scans"
```

---

### Task 6: Server — register the 6 tools

**Files:**
- Create: `servers/tenable-mcp/f0_tenable_mcp/server.py`
- Test: `servers/tenable-mcp/tests/test_tools.py` (add a tool-registration test)

**Interfaces:**
- Consumes: all 6 tool coroutines (Tasks 4–5); `TenableConfig`, `TenableClient`, `redact_obj`.
- Produces: `mcp` (FastMCP "f0-tenable"); `main()`.

- [ ] **Step 1: Write the failing test**

Append to `servers/tenable-mcp/tests/test_tools.py`:

```python
@pytest.mark.asyncio
async def test_server_registers_six_tools():
    from f0_tenable_mcp import server
    names = {t.name for t in await server.mcp.list_tools()}
    assert names == {
        "get_vulnerability_summary", "list_top_vulnerabilities", "list_assets",
        "get_asset_vulnerabilities", "get_vulnerability_info", "list_scans",
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest servers/tenable-mcp/tests/test_tools.py -k registers -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_tenable_mcp.server'`.

- [ ] **Step 3: Implement `server.py`**

`servers/tenable-mcp/f0_tenable_mcp/server.py`:
```python
"""Tenable MCP server (stdio). Read-only tools over the Tenable VM Workbenches API.

Findings are redacted before they leave the server.
"""
from __future__ import annotations

from typing import Any

from dotenv import load_dotenv
from f0_sectools_core.auth.config import TenableConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools
from .client import TenableClient

load_dotenv(".env.tenable")

mcp = FastMCP("f0-tenable")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    return [redact_obj(f.model_dump()) for f in findings]


def _client() -> TenableClient:
    return TenableClient(TenableConfig.from_env())


@mcp.tool()
async def get_vulnerability_summary() -> list[dict[str, Any]]:
    """Tenable environment-wide vulnerability posture — counts by severity.

    Use for "what's our exposure / overall vulnerability posture" questions.
    Returns one posture finding with per-severity instance counts.
    """
    async with _client() as tio:
        return _render(await tools.get_vulnerability_summary(tio))


@mcp.tool()
async def list_top_vulnerabilities(
    severity_min: str = "high", limit: int = 10
) -> list[dict[str, Any]]:
    """Tenable worst vulnerabilities to fix first — ranked by severity then VPR.

    severity_min: low|medium|high|critical (default high). Use for
    "what should we patch first / top risks" questions.
    """
    async with _client() as tio:
        return _render(await tools.list_top_vulnerabilities(tio, severity_min, limit))


@mcp.tool()
async def list_assets(
    hostname: str = "", severity_min: str = "", limit: int = 25
) -> list[dict[str, Any]]:
    """Tenable asset inventory — hosts Tenable has scanned.

    Optional hostname substring filter. Use to find or enumerate assets; for a
    specific host's vulnerabilities use get_asset_vulnerabilities.
    """
    async with _client() as tio:
        return _render(await tools.list_assets(tio, hostname, severity_min, limit))


@mcp.tool()
async def get_asset_vulnerabilities(
    asset: str, severity_min: str = "high", limit: int = 25
) -> list[dict[str, Any]]:
    """Tenable vulnerabilities on ONE host. `asset` is a hostname, IP, or asset UUID.

    Use for "what's wrong with host X / vulnerabilities on X". severity_min:
    low|medium|high|critical (default high).
    """
    async with _client() as tio:
        return _render(
            await tools.get_asset_vulnerabilities(tio, asset, severity_min, limit))


@mcp.tool()
async def get_vulnerability_info(plugin_id: str) -> list[dict[str, Any]]:
    """Tenable detail for one plugin/vulnerability: CVSS, VPR, description, remediation.

    Use to explain a specific Tenable plugin id or get its fix.
    """
    async with _client() as tio:
        return _render(await tools.get_vulnerability_info(tio, plugin_id))


@mcp.tool()
async def list_scans(limit: int = 25) -> list[dict[str, Any]]:
    """Tenable scan inventory — each scan's status and last-run time (coverage freshness)."""
    async with _client() as tio:
        return _render(await tools.list_scans(tio, limit))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest servers/tenable-mcp/tests/test_tools.py -k registers -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add servers/tenable-mcp/f0_tenable_mcp/server.py servers/tenable-mcp/tests/test_tools.py
git commit -m "feat(tenable): FastMCP server registering 6 read tools (redact at boundary)"
```

---

### Task 7: Evals — task set + registration

**Files:**
- Create: `evals/tenable/tasks.yaml`
- Modify: `evals/run.py` (add `"tenable"` to `SERVER_MODULES`), `evals/test_eval_coverage.py` (add `("tenable", ...)` to `SERVERS`)

**Interfaces:**
- Consumes: the 6 registered tool names (Task 6).
- Produces: eval coverage for `tenable` (guard test enforces ≥1 task per tool).

- [ ] **Step 1: Create `evals/tenable/tasks.yaml`**

```yaml
# Small-model tool-calling eval task set — Tenable server.
# See evals/defender/tasks.yaml for the field schema. evals/test_eval_coverage.py
# enforces that every Tenable tool has at least one task.

- prompt: "What's our overall Tenable vulnerability exposure?"
  expect_tool: get_vulnerability_summary

- prompt: "Give me the vulnerability posture across the environment."
  expect_tool: get_vulnerability_summary

- prompt: "Which vulnerabilities should we patch first?"
  expect_tool: list_top_vulnerabilities

- prompt: "Show me the most critical vulnerabilities by risk."
  expect_tool: list_top_vulnerabilities
  expect_args: { severity_min: critical }

- prompt: "List the assets Tenable has scanned."
  expect_tool: list_assets

- prompt: "What vulnerabilities are on host web-01?"
  expect_tool: get_asset_vulnerabilities
  expect_args_contains: { asset: "web-01" }

- prompt: "Explain Tenable plugin 19506 and how to fix it."
  expect_tool: get_vulnerability_info
  expect_args_contains: { plugin_id: "19506" }

- prompt: "Are our Tenable scans running and up to date?"
  expect_tool: list_scans
```

- [ ] **Step 2: Register in `evals/run.py`**

In `SERVER_MODULES` (after the `intune` line), add:
```python
    "tenable": "f0_tenable_mcp.server",
```

- [ ] **Step 3: Register in `evals/test_eval_coverage.py`**

In `SERVERS` (after the `intune` tuple), add:
```python
    ("tenable", "f0_tenable_mcp.server"),
```

- [ ] **Step 4: Run the coverage guard**

Run: `uv run pytest evals/test_eval_coverage.py -v`
Expected: PASS — every Tenable tool has ≥1 task; every task names a real tool.

- [ ] **Step 5: Commit**

```bash
git add evals/tenable/tasks.yaml evals/run.py evals/test_eval_coverage.py
git commit -m "feat(tenable): eval task set + register in harness (combined 28->34 tools)"
```

---

### Task 8: Live smoke script (with --persona)

**Files:**
- Create: `scripts/live_smoke_tenable.py`

**Interfaces:**
- Consumes: `TenableConfig`, `TenableClient`, the 6 tool coroutines, `render_findings`/`Persona` (renderers), `redact_obj`.

- [ ] **Step 1: Create `scripts/live_smoke_tenable.py`**

Mirror `scripts/live_smoke_defender.py`'s persona wiring:
```python
"""Live smoke test for the Tenable MCP server against a real Tenable VM instance.

Usage (from the repo root):
    1. Copy servers/tenable-mcp/.env.tenable.example to ./.env.tenable and fill in
       TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY.
    2. uv run python scripts/live_smoke_tenable.py [--persona ciso]

Calls each read tool against live Tenable and prints REDACTED findings. Secrets are
never printed. Auth / permission / rate-limit issues show up as posture findings
(graceful degradation), not crashes.
"""
from __future__ import annotations

import argparse
import asyncio
import json

from dotenv import load_dotenv
from f0_sectools_core.auth.config import TenableConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.renderers import Persona, render_findings
from f0_tenable_mcp import tools
from f0_tenable_mcp.client import TenableClient

load_dotenv(".env.tenable")


def _show(label: str, findings, persona: str | None = None) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:8]:
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 8:
        print(f"... ({len(findings) - 8} more)")
    if persona is not None:
        print(f"\n--- {persona} view ---")
        print(render_findings(findings, persona))


async def main(persona: str | None = None) -> None:
    cfg = TenableConfig.from_env()  # raises clearly if creds missing
    print(f"Instance {cfg.base_url}  (api keys not shown)")
    async with TenableClient(cfg) as tio:
        # get an asset id for the per-asset call from the asset list
        assets = await tools.list_assets(tio, limit=1)
        first_asset = assets[0].entity.name if assets and assets[0].entity else "localhost"
        for label, coro in [
            ("get_vulnerability_summary", tools.get_vulnerability_summary(tio)),
            ("list_top_vulnerabilities", tools.list_top_vulnerabilities(tio, limit=5)),
            ("list_assets", tools.list_assets(tio, limit=5)),
            ("get_asset_vulnerabilities", tools.get_asset_vulnerabilities(tio, first_asset, limit=5)),
            ("list_scans", tools.list_scans(tio, limit=5)),
        ]:
            try:
                _show(label, await coro, persona)
            except Exception as e:  # noqa: BLE001 — smoke test: report and continue
                print(f"\n=== {label}: ERROR ===\n{type(e).__name__}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live smoke test for the Tenable MCP server.")
    parser.add_argument(
        "--persona",
        choices=[p.value for p in Persona],
        default=None,
        help="Also print findings rendered for this persona (raw JSON is always shown).",
    )
    args = parser.parse_args()
    asyncio.run(main(args.persona))
```

> `get_vulnerability_info` is intentionally not in the smoke loop by default (it needs a
> real plugin id). Live validation adds a call with an id surfaced by
> `list_top_vulnerabilities`.

- [ ] **Step 2: Verify it imports (no network)**

Run: `uv run python -c "import ast; ast.parse(open('scripts/live_smoke_tenable.py').read()); print('ok')"`
Expected: `ok`. (It cannot run fully without `.env.tenable` — that's the user-gated live step.)

- [ ] **Step 3: Commit**

```bash
git add scripts/live_smoke_tenable.py
git commit -m "feat(tenable): live smoke script with --persona"
```

---

### Task 9: Skills (3 SKILL.md)

**Files:**
- Create: `skills/tenable/exposure-posture-review/SKILL.md`, `skills/tenable/host-vulnerability-triage/SKILL.md`, `skills/tenable/scan-coverage-review/SKILL.md`

**Interfaces:**
- Consumes: tool base names (Task 6). Referenced by base name (runtimes prefix).
- Constraint: `skills/test_skills_valid.py` enforces valid frontmatter and **`description` ≤60 chars**.

- [ ] **Step 1: Create `skills/tenable/exposure-posture-review/SKILL.md`** (default focus)

```markdown
---
name: review-exposure-posture
description: Review Tenable vulnerability exposure and fix-first list
version: 1.0.0
metadata:
  hermes:
    tags: [security, tenable, vulnerability, posture, ciso]
    category: security
---

# Review Tenable Exposure Posture

## When to Use

The user wants the vulnerability-exposure picture — "what's our Tenable exposure",
"what should we patch first", "give me a CISO vulnerability summary". Uses the
**f0_sectools Tenable** MCP server (read-only). This is the default Tenable focus.

## Tools

Base tool names (runtime may prefix — see the Tenable server README):
`get_vulnerability_summary`, `list_top_vulnerabilities` (set `severity_min`),
`list_scans`. Read-only.

## Procedure

1. Call `get_vulnerability_summary` for the headline — total findings and the
   per-severity breakdown (critical/high/medium/low).
2. Call `list_top_vulnerabilities` (severity_min=high) for the fix-first list,
   ranked by severity then VPR.
3. Call `list_scans` to check scan freshness — a stale scan means the posture
   picture may be out of date; note it as a caveat.
4. Summarize for the audience: exposure by severity, the top 2-3 vulnerabilities
   to remediate, and any scan-freshness caveat.

## Pitfalls

- Do not claim full coverage if `list_scans` shows stale or missing scans.
- Report only what the tools return; never invent CVE ids or counts.

## Verification

Posture % / counts trace to `get_vulnerability_summary`; each fix-first item traces
to a `list_top_vulnerabilities` finding.

## Discipline (small local models)

- One tool at a time; report only what the tools return.
```

- [ ] **Step 2: Create `skills/tenable/host-vulnerability-triage/SKILL.md`**

```markdown
---
name: triage-host-vulnerabilities
description: Enumerate and triage one host's Tenable vulnerabilities
version: 1.0.0
metadata:
  hermes:
    tags: [security, tenable, vulnerability, host, soc]
    category: security
---

# Triage a Host's Tenable Vulnerabilities

## When to Use

The user wants to investigate a specific host — "what's wrong with web-01",
"vulnerabilities on 10.0.0.5", "triage this asset". Uses the **f0_sectools
Tenable** MCP server (read-only).

## Tools

Base tool names: `list_assets` (find/confirm the host), `get_asset_vulnerabilities`
(the host's vulnerabilities; `asset` accepts hostname/ip/UUID), `get_vulnerability_info`
(fix detail for the worst plugins). Read-only.

## Procedure

1. If unsure of the exact host name, call `list_assets` with a `hostname` filter to
   confirm the asset.
2. Call `get_asset_vulnerabilities` with the hostname/ip (severity_min=high) to
   enumerate the host's high/critical vulnerabilities.
3. For the top 1-3 findings, call `get_vulnerability_info` with the plugin id to get
   CVSS/VPR, description, and remediation.
4. Summarize: the host, its worst vulnerabilities, and the concrete fix for each.

## Pitfalls

- If `get_asset_vulnerabilities` returns a "no asset matches" posture finding, re-run
  `list_assets` to find the exact name — do not guess a UUID.
- Report only what the tools return.

## Verification

Every reported vulnerability traces to a `get_asset_vulnerabilities` finding for the
named host; each remediation traces to a `get_vulnerability_info` finding.

## Discipline (small local models)

- One tool at a time; feed the resolved host/plugin id forward.
```

- [ ] **Step 3: Create `skills/tenable/scan-coverage-review/SKILL.md`**

```markdown
---
name: review-scan-coverage
description: Review Tenable scan coverage and freshness gaps
version: 1.0.0
metadata:
  hermes:
    tags: [security, tenable, scans, coverage, engineer]
    category: security
---

# Review Tenable Scan Coverage

## When to Use

The user wants to know whether scanning is actually covering the environment —
"are our Tenable scans running", "what's our scan coverage", "any blind spots".
Uses the **f0_sectools Tenable** MCP server (read-only).

## Tools

Base tool names: `list_scans` (scan inventory + status + last-run),
`list_assets` (what's in the inventory). Read-only.

## Procedure

1. Call `list_scans` — review each scan's status and last-run time; flag any that
   are failed, disabled, or stale (not run recently).
2. Call `list_assets` to gauge the asset inventory the scans should be covering.
3. Summarize: which scans are healthy vs stale/failed, and where coverage looks
   thin (assets present but scans not recent).

## Pitfalls

- "Completed" status with an old last-run is still stale — judge on freshness, not
  status alone.
- Report only what the tools return.

## Verification

Each coverage claim traces to a `list_scans` status/last-run value.

## Discipline (small local models)

- One tool at a time; report only what the tools return.
```

- [ ] **Step 4: Run the skills validity test**

Run: `uv run pytest skills/test_skills_valid.py -v`
Expected: PASS — all three new `SKILL.md` have valid frontmatter and ≤60-char descriptions.
(The three descriptions above are 44, 47, and 43 chars.)

- [ ] **Step 5: Commit**

```bash
git add skills/tenable/
git commit -m "feat(tenable): 3 skills (exposure-posture default, host-triage, scan-coverage)"
```

---

### Task 10: Docs

**Files:**
- Modify: `CLAUDE.md` (Architecture tree, Platform Integrations "Implemented & live-validated" note, skills list), `README.md` (server status), `docs/user-guide/README.md` (support matrix + a Tenable workflow)

**Interfaces:** none (docs only).

- [ ] **Step 1: Update `CLAUDE.md`**

In the Architecture tree `servers/` block, add under `intune-mcp/`:
```
    tenable-mcp/            # built (live-validation pending)
```
In the `skills/` block, add:
```
    tenable/                # exposure-posture-review, host-vulnerability-triage, scan-coverage-review
```
In the skills paragraph under "Skills (one portable set)", add to the current-skills sentence:
`, tenable/{exposure-posture-review,host-vulnerability-triage,scan-coverage-review} (exposure-posture review is the Tenable default focus)`.
In the Platform Integrations table, the Tenable row already exists — confirm it reads read-only (no gated write). No table change needed beyond confirming.

- [ ] **Step 2: Update `README.md`**

Wherever server status is listed (the servers/status section), add `tenable-mcp` as **built (live-validation pending)**, read-only, 6 tools.

- [ ] **Step 3: Update `docs/user-guide/README.md`**

Add Tenable to the support matrix (server: Tenable VM, auth: API keys, read tools: vulnerabilities/assets/scans, gated write: —) and add a short "Tenable exposure review" workflow entry pointing at the `exposure-posture-review` skill.

- [ ] **Step 4: Verify markdown + no broken internal links**

Run: `uv run pytest skills/test_skills_valid.py evals/test_eval_coverage.py -q`
Expected: PASS (docs edits don't break tests; this re-confirms skills/evals still green).

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md docs/user-guide/README.md
git commit -m "docs(tenable): add tenable-mcp to architecture, status, and user guide"
```

---

### Task 11: Full verification pass

**Files:** none (verification only).

- [ ] **Step 1: Full test suite**

Run: `uv run pytest`
Expected: PASS — all existing + new tests (config, tenable contract, eval coverage, skills validity).

- [ ] **Step 2: Lint**

Run: `uv run ruff check .`
Expected: no errors. (Fix any import ordering / line length in the new files.)

- [ ] **Step 3: Type-check (shipped source, strict)**

Run: `uv run mypy .`
Expected: no errors in `core/` and `servers/tenable-mcp/f0_tenable_mcp/`.

- [ ] **Step 4: Confirm the server starts and lists tools**

Run: `uv run python -c "import asyncio; from f0_tenable_mcp import server; print(sorted(t.name for t in asyncio.run(server.mcp.list_tools())))"`
Expected: the 6 tool names printed.

- [ ] **Step 5: Commit any lint/type fixes**

```bash
git add -u
git commit -m "chore(tenable): lint + type-check fixes" || echo "nothing to fix"
```

---

## Task 12 (USER-GATED — do NOT run as a subagent): Live validation

This is recipe step 9 and is **gated on the user** (hits a real Tenable tenant with real keys). It runs after Task 11, interactively, not as part of automated execution.

1. **User** copies `servers/tenable-mcp/.env.tenable.example` → `./.env.tenable` and fills in real `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY`. (Claude never handles the keys.)
2. Run `uv run python scripts/live_smoke_tenable.py` **with network enabled**.
3. Fix-forward the 1–3 field-name/endpoint mismatches live data reveals (e.g. the
   real `vulnerabilities` row key, the asset fqdn/ipv4 field, the scan last-run field,
   whether a summary endpoint exists vs client-side aggregation). Update the tools and
   their contract-test mocks together.
4. Optionally run `uv run python scripts/live_smoke_tenable.py --persona ciso` to
   sanity-check the renderer view.
5. Once clean, update the CLAUDE.md note from "live-validation pending" to
   "live-validated", and (optionally) refresh the eval scorecard for the 34-tool registry.

---

## Self-Review

**1. Spec coverage:**
- TenableConfig + test → Task 1 ✅
- Scaffold (pyproject/README/.env.example/__init__) → Task 2 ✅
- client.py (X-ApiKeys) → Task 3 ✅
- errors.py (map_tenable_error, 401/403/429/5xx) → Task 3 ✅
- 6 tools + asset resolution + findings mapping, contract-tests-first → Tasks 4–5 ✅
- server.py (FastMCP, redact at boundary, platform-anchored docstrings) → Task 6 ✅
- evals tasks.yaml + run.py + test_eval_coverage → Task 7 ✅
- live_smoke + --persona → Task 8 ✅
- 3 skills, exposure-posture default → Task 9 ✅
- docs → Task 10 ✅
- verify (pytest/ruff/mypy) → Task 11 ✅
- live validation user-gated → Task 12 ✅
- No core changes beyond TenableConfig ✅ ; no gated writes ✅

**2. Placeholder scan:** No TBD/TODO. The "assumed field names" are explicit, real code with real mock shapes, flagged for live validation — the established pattern, not a placeholder.

**3. Type consistency:** tool signatures in Tasks 4–5 match the `server.py` calls in Task 6 and the smoke calls in Task 8 (`get_vulnerability_summary(tio)`, `list_top_vulnerabilities(tio, severity_min, limit)`, `list_assets(tio, hostname, severity_min, limit)`, `get_asset_vulnerabilities(tio, asset, severity_min, limit)`, `get_vulnerability_info(tio, plugin_id)`, `list_scans(tio, limit)`). Helper names (`_sev`, `_rows`, `_cves`, `_UUID_RE`, `_SEV_MIN`, `_resolve_asset_uuid`) are defined before use. `map_tenable_error` uses `Finding.api_unavailable` which exists in the schema. Server name `f0-tenable`; module `f0_tenable_mcp.server`.
