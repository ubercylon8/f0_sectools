# f0_sectools — Core + Microsoft Defender/Entra Servers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the f0_sectools workspace, build the shared `core/` foundation (findings schema, redaction, gated actions, Microsoft Graph client), and implement read-only MCP servers for Microsoft Defender XDR and Microsoft Entra ID.

**Architecture:** A uv workspace with a shared `core` package and thin per-platform MCP servers. All safety-critical logic (schema, redaction, auth, gating) lives in `core` and is imported by servers. The Defender and Entra servers share one async Microsoft Graph client (ported from ProjectAchilles' proven TypeScript `MicrosoftGraphClient`), authenticate via OAuth2 client-credentials, and are **permission-aware**: a Graph `403` degrades to a "permission not granted" finding rather than a crash.

**Tech Stack:** Python 3.11+, `uv` workspace, `pydantic` v2 (schema), `httpx` (async Graph client), `mcp` (MCP server SDK), `pytest` + `pytest-asyncio` + `respx` (HTTP mocking), `ruff` (lint incl. bandit `S` rules).

## Global Constraints

- **Read-only by default.** Every tool in this plan is read-only. No write/response action ships in this plan. The gating module is built and unit-tested, but no server registers a gated write yet.
- **Secrets never logged, never returned, never sent to the model, never leave the host.** Credentials live only in `core/auth`.
- **Every tool returns the findings schema** (`Finding` / list of `Finding`). No ad-hoc text.
- **All safety logic lives in `core/`.** Servers must not re-implement redaction, auth, schema, paging, or gating.
- **Small-model-safe tools:** flat scalar args, short closed enums, ≤ ~8 tools per server, bounded/paginated output.
- **Per-platform `.env`:** `.env.defender`, `.env.entra` (both gitignored). One Azure app registration may serve both.
- **Graph API generation:** use the **v2 / Defender XDR** endpoints (`/security/alerts_v2`, `/security/incidents`, `/security/runHuntingQuery`) gated by `SecurityAlert.Read.All` / `SecurityIncident.Read.All` / `ThreatHunting.Read.All` — NOT the legacy `/security/alerts` (`SecurityEvents.Read.All`).
- **Graph base URL:** `https://graph.microsoft.com/v1.0`. **Token endpoint:** `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`, scope `https://graph.microsoft.com/.default`.
- **Conventional commits; never push** — commit locally, surface the hash, wait for explicit push instruction.

## Recommended app-registration permissions (documented in `.env.*.example`)

All **Application** type, read-only, admin consent required.

- **Defender (`.env.defender`):** `SecurityIncident.Read.All`, `SecurityAlert.Read.All`, `ThreatHunting.Read.All`, plus existing `SecurityEvents.Read.All` (legacy secure-score/control-profile fallback).
- **Entra (`.env.entra`):** existing `Directory.Read.All`, `Policy.Read.All`, `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory`; **add** `AuditLog.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`. Tier-2 optional: `Application.Read.All`, `IdentityRiskyServicePrincipal.Read.All`, `Reports.Read.All`, `Device.Read.All`, `DeviceManagementManagedDevices.Read.All`.
- **Licensing caveats (documented):** Identity Protection perms need Entra ID **P2**; Defender XDR incident/hunting need **Defender** licensing. Servers degrade gracefully when a permission or license is absent.

---

## File Structure

```
core/f0_sectools_core/
  schema/findings.py        Finding/Entity/Evidence/RecommendedAction/Reference + enums + helpers
  redaction/redact.py       redact_text(), redact_obj() — secret/PII stripping
  redaction/patterns.py     compiled secret/PII regexes
  auth/config.py            PlatformConfig.from_env(prefix) — per-platform .env loader
  auth/graph.py             GraphClient — async token cache, pagination, 429/401 retry
  gating/actions.py         GatedAction, confirmation-token + flag gate, AuditLog
  smallmodel/enums.py       coerce_enum() — forgiving enum guard for tool args
servers/defender-mcp/
  f0_defender_mcp/server.py MCP server: tools + registration
  f0_defender_mcp/tools.py  tool implementations (Graph calls -> findings)
  pyproject.toml
  .env.defender.example
  tests/test_tools.py
servers/entra-mcp/
  f0_entra_mcp/server.py
  f0_entra_mcp/tools.py
  pyproject.toml
  .env.entra.example
  tests/test_tools.py
evals/defender/tasks.yaml   small-model callability tasks for Defender tools
evals/entra/tasks.yaml      small-model callability tasks for Entra tools
core/tests/                 unit tests for schema, redaction, gating, graph client
```

---

# Phase 1 — Workspace setup

### Task 1: Rename branch and materialize the workspace

**Files:**
- Modify: `pyproject.toml` (add `respx`, `httpx`, `mcp` to dev/runtime as below)

**Interfaces:**
- Produces: a synced `.venv` with `pytest`, `ruff`, importable `f0_sectools_core`.

- [ ] **Step 1: Rename default branch to `main`**

```bash
git branch -m main
git branch --show-current   # expect: main
```

- [ ] **Step 2: Make the root a virtual workspace coordinator and add dev tooling**

The root must NOT be a distributable package, and dev tools belong in a
dependency group (not a project extra) so `uv sync` installs them by default.
In `pyproject.toml`, replace `[project.optional-dependencies]` with:

```toml
[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "respx>=0.21",
    "ruff>=0.6",
    "mypy>=1.10",
]

[tool.uv]
package = false
```

And add to `core/pyproject.toml` dependencies: `"httpx>=0.27"` (alongside `pydantic>=2.7`).

- [ ] **Step 3: Sync the whole workspace**

Run: `uv sync --all-packages`
Expected: builds/installs `f0-sectools-core` editable plus its deps (pydantic,
httpx) and the dev group (pytest, respx, ruff) into `.venv`. (Plain `uv sync`
installs only the root's deps, NOT workspace members — always use
`--all-packages` here.)

- [ ] **Step 4: Verify tooling runs**

Run: `uv run pytest -q` → Expected: "no tests ran" (exit 5) — acceptable, confirms pytest works.
Run: `uv run ruff check .` → Expected: passes (no Python files with violations yet).

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml core/pyproject.toml uv.lock
git commit -m "chore: rename branch to main and sync uv workspace deps"
```

---

# Phase 2 — Core foundation

### Task 2: Findings schema

**Files:**
- Create: `core/f0_sectools_core/schema/findings.py`
- Test: `core/tests/test_findings.py`

**Interfaces:**
- Produces:
  - Enums `Severity` (`info|low|medium|high|critical`), `EntityKind` (`host|user|file|ip|account|app|service_principal|role|policy|rule|tenant|device`), `FindingType` (`alert|incident|misconfig|risk|ioc|posture|hunt_result|action`).
  - `Entity(kind: EntityKind, id: str, name: str | None = None)`
  - `Evidence(key: str, value: str)`
  - `Reference(type: str, id: str, url: str | None = None)`
  - `RecommendedAction(summary: str, gated_action: str | None = None, confidence: str = "medium")`
  - `Finding(source: str, finding_type: FindingType, severity: Severity, title: str, entity: Entity | None = None, evidence: list[Evidence] = [], recommended_action: RecommendedAction | None = None, references: list[Reference] = [], observed_at: str | None = None, schema_version: str = "1.0")`
  - `Finding.permission_missing(source, permission, capability) -> Finding` classmethod that builds an `info`/`posture` finding telling the operator which Graph permission to grant.

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_findings.py
from f0_sectools_core.schema.findings import (
    Finding, Entity, Evidence, RecommendedAction, Severity, EntityKind, FindingType,
)

def test_finding_roundtrips_to_dict():
    f = Finding(
        source="defender",
        finding_type=FindingType.incident,
        severity=Severity.high,
        title="Multi-stage incident on web-01",
        entity=Entity(kind=EntityKind.host, id="web-01"),
        evidence=[Evidence(key="alerts", value="3")],
        recommended_action=RecommendedAction(summary="Investigate incident"),
    )
    d = f.model_dump()
    assert d["schema_version"] == "1.0"
    assert d["severity"] == "high"
    assert d["entity"]["kind"] == "host"
    assert d["recommended_action"]["gated_action"] is None

def test_permission_missing_helper():
    f = Finding.permission_missing("entra", "IdentityRiskyUser.Read.All", "risky users")
    assert f.severity == Severity.info
    assert f.finding_type == FindingType.posture
    assert "IdentityRiskyUser.Read.All" in f.title
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_findings.py -v`
Expected: FAIL — `ModuleNotFoundError: f0_sectools_core.schema.findings`.

- [ ] **Step 3: Implement the schema**

```python
# core/f0_sectools_core/schema/findings.py
"""Normalized findings schema. Every f0_sectools tool returns Finding(s)."""
from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    info = "info"; low = "low"; medium = "medium"; high = "high"; critical = "critical"


class EntityKind(str, Enum):
    host = "host"; user = "user"; file = "file"; ip = "ip"; account = "account"
    app = "app"; service_principal = "service_principal"; role = "role"
    policy = "policy"; rule = "rule"; tenant = "tenant"; device = "device"


class FindingType(str, Enum):
    alert = "alert"; incident = "incident"; misconfig = "misconfig"; risk = "risk"
    ioc = "ioc"; posture = "posture"; hunt_result = "hunt_result"; action = "action"


class Entity(BaseModel):
    kind: EntityKind
    id: str
    name: str | None = None


class Evidence(BaseModel):
    key: str
    value: str


class Reference(BaseModel):
    type: str
    id: str
    url: str | None = None


class RecommendedAction(BaseModel):
    summary: str
    gated_action: str | None = None
    confidence: str = "medium"


class Finding(BaseModel):
    schema_version: str = "1.0"
    source: str
    finding_type: FindingType
    severity: Severity
    title: str
    entity: Entity | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    recommended_action: RecommendedAction | None = None
    references: list[Reference] = Field(default_factory=list)
    observed_at: str | None = None

    @classmethod
    def permission_missing(cls, source: str, permission: str, capability: str) -> "Finding":
        return cls(
            source=source,
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Permission '{permission}' not granted — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary=f"Grant the application permission '{permission}' (admin consent) to enable {capability}.",
                confidence="high",
            ),
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest core/tests/test_findings.py -v` → Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/schema/findings.py core/tests/test_findings.py
git commit -m "feat(core): add normalized findings schema"
```

---

### Task 3: Redaction

**Files:**
- Create: `core/f0_sectools_core/redaction/patterns.py`, `core/f0_sectools_core/redaction/redact.py`
- Test: `core/tests/test_redaction.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `redact_text(text: str) -> str` — replaces secrets/tokens with `«redacted»`.
  - `redact_obj(obj: Any) -> Any` — deep-redacts dict/list/str; redacts values of keys named like secrets (`*secret*`, `*password*`, `*token*`, `client_secret`, `authorization`) and any string matching a secret pattern.

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_redaction.py
from f0_sectools_core.redaction.redact import redact_text, redact_obj

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
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest core/tests/test_redaction.py -v` → Expected: FAIL (module missing).

- [ ] **Step 3: Implement**

```python
# core/f0_sectools_core/redaction/patterns.py
"""Compiled secret/PII regexes used by the redaction layer."""
import re

REDACTED = "«redacted»"

# Keys whose values are always secrets, matched case-insensitively as substrings.
SECRET_KEY_HINTS = ("secret", "password", "passwd", "token", "authorization", "api_key", "apikey", "client_secret")

# Value patterns that look like secrets/tokens regardless of key.
SECRET_VALUE_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{12,}", re.IGNORECASE),
    re.compile(r"eyJ[A-Za-z0-9._\-]{20,}"),          # JWT
    re.compile(r"[A-Za-z0-9_\-]{32,}\.[A-Za-z0-9_\-]{6,}"),  # client-secret-ish
]
```

```python
# core/f0_sectools_core/redaction/redact.py
"""Strip secrets/PII from all tool output, including error paths."""
from __future__ import annotations
from typing import Any
from .patterns import REDACTED, SECRET_KEY_HINTS, SECRET_VALUE_PATTERNS


def redact_text(text: str) -> str:
    out = text
    for pat in SECRET_VALUE_PATTERNS:
        out = pat.sub(REDACTED, out)
    return out


def _key_is_secret(key: str) -> bool:
    k = key.lower()
    return any(hint in k for hint in SECRET_KEY_HINTS)


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: (REDACTED if _key_is_secret(str(k)) else redact_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest core/tests/test_redaction.py -v` → Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/redaction/ core/tests/test_redaction.py
git commit -m "feat(core): add redaction layer for secrets and PII"
```

---

### Task 4: Gated actions + audit log

**Files:**
- Create: `core/f0_sectools_core/gating/actions.py`
- Test: `core/tests/test_gating.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `class GateDenied(Exception)`
  - `class AuditLog` with `__init__(self, path: str | None = None)` and `record(self, action: str, target: str, actor: str, token: str) -> None` (appends a JSON line; no secrets).
  - `class GatedAction(name: str, enabled: bool, audit: AuditLog)` with `execute(self, *, target: str, actor: str, token: str | None, run: Callable[[], Any]) -> Any` that raises `GateDenied` unless `enabled is True` AND `token` is a non-empty string; on success calls `run()`, records the audit entry, returns the result.

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_gating.py
import json
import pytest
from f0_sectools_core.gating.actions import GatedAction, AuditLog, GateDenied

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
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest core/tests/test_gating.py -v` → Expected: FAIL (module missing).

- [ ] **Step 3: Implement**

```python
# core/f0_sectools_core/gating/actions.py
"""Gated write-action machinery: config flag + confirmation token + audit log."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Callable


class GateDenied(Exception):
    """Raised when a gated action is attempted without flag or token."""


class AuditLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else Path("audit-logs/actions.log")

    def record(self, action: str, target: str, actor: str, token: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"action": action, "target": target, "actor": actor, "token": token}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


class GatedAction:
    def __init__(self, name: str, enabled: bool, audit: AuditLog) -> None:
        self.name = name
        self.enabled = enabled
        self.audit = audit

    def execute(self, *, target: str, actor: str, token: str | None, run: Callable[[], Any]) -> Any:
        if not self.enabled:
            raise GateDenied(f"Action '{self.name}' is disabled. Set the platform write flag to enable it.")
        if not token:
            raise GateDenied(f"Action '{self.name}' requires a human confirmation token.")
        result = run()
        self.audit.record(self.name, target, actor, token)
        return result
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest core/tests/test_gating.py -v` → Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/gating/actions.py core/tests/test_gating.py
git commit -m "feat(core): add gated-action machinery with audit log"
```

---

### Task 5: Platform config loader

**Files:**
- Create: `core/f0_sectools_core/auth/config.py`
- Test: `core/tests/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `@dataclass PlatformConfig(tenant_id: str, client_id: str, client_secret: str, verify_tls: bool = True, allow_write: bool = False, extra: dict[str, str] = {})`
  - `PlatformConfig.from_env(prefix: str, env: Mapping[str, str] | None = None) -> PlatformConfig` reading `{PREFIX}_TENANT_ID`, `{PREFIX}_CLIENT_ID`, `{PREFIX}_CLIENT_SECRET`, optional `{PREFIX}_VERIFY_TLS` (default true), `{PREFIX}_ALLOW_WRITE` (default false). Raises `ValueError` listing any missing required vars. Never logs values.

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_config.py
import pytest
from f0_sectools_core.auth.config import PlatformConfig

def test_loads_from_env_mapping():
    env = {"DEFENDER_TENANT_ID": "t", "DEFENDER_CLIENT_ID": "c", "DEFENDER_CLIENT_SECRET": "s"}
    cfg = PlatformConfig.from_env("DEFENDER", env=env)
    assert cfg.tenant_id == "t" and cfg.verify_tls is True and cfg.allow_write is False

def test_missing_vars_raises_listing_names():
    with pytest.raises(ValueError) as e:
        PlatformConfig.from_env("ENTRA", env={})
    assert "ENTRA_TENANT_ID" in str(e.value)

def test_allow_write_and_verify_flags():
    env = {"X_TENANT_ID": "t", "X_CLIENT_ID": "c", "X_CLIENT_SECRET": "s",
           "X_VERIFY_TLS": "false", "X_ALLOW_WRITE": "true"}
    cfg = PlatformConfig.from_env("X", env=env)
    assert cfg.verify_tls is False and cfg.allow_write is True
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest core/tests/test_config.py -v` → Expected: FAIL (module missing).

- [ ] **Step 3: Implement**

```python
# core/f0_sectools_core/auth/config.py
"""Per-platform credential loading. Secrets never leave this layer or get logged."""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Mapping

_TRUE = {"1", "true", "yes", "on"}


@dataclass
class PlatformConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    verify_tls: bool = True
    allow_write: bool = False
    extra: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, prefix: str, env: Mapping[str, str] | None = None) -> "PlatformConfig":
        env = env if env is not None else os.environ
        required = {k: f"{prefix}_{k.upper()}" for k in ("tenant_id", "client_id", "client_secret")}
        missing = [name for name in required.values() if not env.get(name)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
        verify = env.get(f"{prefix}_VERIFY_TLS", "true").strip().lower() in _TRUE
        allow_write = env.get(f"{prefix}_ALLOW_WRITE", "false").strip().lower() in _TRUE
        return cls(
            tenant_id=env[required["tenant_id"]],
            client_id=env[required["client_id"]],
            client_secret=env[required["client_secret"]],
            verify_tls=verify,
            allow_write=allow_write,
        )
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest core/tests/test_config.py -v` → Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/auth/config.py core/tests/test_config.py
git commit -m "feat(core): add per-platform .env config loader"
```

---

### Task 6: Microsoft Graph client (port of ProjectAchilles patterns)

**Files:**
- Create: `core/f0_sectools_core/auth/graph.py`
- Test: `core/tests/test_graph.py`

**Interfaces:**
- Consumes: `PlatformConfig` (for tenant/client/secret/verify_tls).
- Produces:
  - `class GraphError(Exception)` with attributes `status: int`, `message: str` (redacted).
  - `class GraphClient(config: PlatformConfig, base_url: str = "https://graph.microsoft.com/v1.0")` (async). Methods:
    - `async get_token() -> str` — client-credentials, cached with 300s refresh margin.
    - `async get(path: str, params: dict | None = None) -> dict` — single GET returning parsed JSON; raises `GraphError` on non-2xx (message redacted), refreshes token once on 401, retries up to 3× on 429 honoring `Retry-After`.
    - `async get_all(path: str, params: dict | None = None) -> list[dict]` — follows `@odata.nextLink`, returns the concatenated `value` arrays.
    - `async post(path: str, json_body: dict) -> dict` — for `runHuntingQuery` (read-only POST).
  - Uses one `httpx.AsyncClient` (verify=config.verify_tls); usable as async context manager (`async with GraphClient(...) as gc:`).

- [ ] **Step 1: Write the failing test (token + pagination + 429, mocked with respx)**

```python
# core/tests/test_graph.py
import httpx, pytest, respx
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient, GraphError

CFG = PlatformConfig(tenant_id="t", client_id="c", client_secret="s")
TOKEN_URL = "https://login.microsoftonline.com/t/oauth2/v2.0/token"

def _token_route(mock):
    mock.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600}))

@pytest.mark.asyncio
@respx.mock
async def test_get_all_follows_nextlink():
    _token_route(respx)
    base = "https://graph.microsoft.com/v1.0/security/incidents"
    respx.get(base).mock(return_value=httpx.Response(200, json={
        "value": [{"id": "1"}], "@odata.nextLink": base + "?$skiptoken=abc"}))
    respx.get(base + "?$skiptoken=abc").mock(return_value=httpx.Response(200, json={"value": [{"id": "2"}]}))
    async with GraphClient(CFG) as gc:
        items = await gc.get_all("/security/incidents")
    assert [i["id"] for i in items] == ["1", "2"]

@pytest.mark.asyncio
@respx.mock
async def test_get_raises_grapherror_on_403():
    _token_route(respx)
    respx.get("https://graph.microsoft.com/v1.0/security/incidents").mock(
        return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}}))
    async with GraphClient(CFG) as gc:
        with pytest.raises(GraphError) as e:
            await gc.get("/security/incidents")
    assert e.value.status == 403
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest core/tests/test_graph.py -v` → Expected: FAIL (module missing).

- [ ] **Step 3: Implement**

```python
# core/f0_sectools_core/auth/graph.py
"""Async Microsoft Graph client: token cache, pagination, 429/401 retry.

Ported from ProjectAchilles' MicrosoftGraphClient (backend/src/services/defender/
graph-client.ts): client-credentials grant, 300s token refresh margin,
@odata.nextLink pagination, Retry-After backoff, one-shot 401 refresh.
"""
from __future__ import annotations
import asyncio, time
from typing import Any
import httpx
from .config import PlatformConfig
from ..redaction.redact import redact_text

TOKEN_REFRESH_MARGIN_S = 300
MAX_RETRIES = 3


class GraphError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = redact_text(message)
        super().__init__(f"Graph HTTP {status}: {self.message}")


class GraphClient:
    def __init__(self, config: PlatformConfig, base_url: str = "https://graph.microsoft.com/v1.0") -> None:
        self._cfg = config
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(verify=config.verify_tls, timeout=60.0)
        self._token: str | None = None
        self._token_exp: float = 0.0

    async def __aenter__(self) -> "GraphClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def get_token(self) -> str:
        now = time.time()
        if self._token and self._token_exp > now + TOKEN_REFRESH_MARGIN_S:
            return self._token
        url = f"https://login.microsoftonline.com/{self._cfg.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._cfg.client_id,
            "client_secret": self._cfg.client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }
        resp = await self._client.post(url, data=data)
        if resp.status_code != 200:
            raise GraphError(resp.status_code, "token request failed")
        payload = resp.json()
        self._token = payload["access_token"]
        self._token_exp = now + int(payload.get("expires_in", 3600))
        return self._token

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    async def _request(self, method: str, path: str, *, params: dict | None = None,
                       json_body: dict | None = None) -> dict:
        for attempt in range(MAX_RETRIES + 1):
            token = await self.get_token()
            headers = {"Authorization": f"Bearer {token}"}
            resp = await self._client.request(method, self._url(path), params=params,
                                              json=json_body, headers=headers)
            if resp.status_code == 401 and attempt == 0:
                self._token = None  # force refresh, retry once
                continue
            if resp.status_code == 429 and attempt < MAX_RETRIES:
                await asyncio.sleep(float(resp.headers.get("Retry-After", "1")))
                continue
            if resp.status_code // 100 != 2:
                msg = ""
                try:
                    msg = resp.json().get("error", {}).get("message", "")
                except Exception:
                    msg = resp.text
                raise GraphError(resp.status_code, msg or "request failed")
            return resp.json() if resp.content else {}
        raise GraphError(429, "exceeded retry budget")

    async def get(self, path: str, params: dict | None = None) -> dict:
        return await self._request("GET", path, params=params)

    async def post(self, path: str, json_body: dict) -> dict:
        return await self._request("POST", path, json_body=json_body)

    async def get_all(self, path: str, params: dict | None = None) -> list[dict]:
        items: list[dict] = []
        page = await self._request("GET", path, params=params)
        items.extend(page.get("value", []))
        next_link = page.get("@odata.nextLink")
        while next_link:
            page = await self._request("GET", next_link)
            items.extend(page.get("value", []))
            next_link = page.get("@odata.nextLink")
        return items
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest core/tests/test_graph.py -v` → Expected: 2 passed.

- [ ] **Step 5: Run the full core suite + lint**

Run: `uv run pytest core/ -q` → Expected: all pass.
Run: `uv run ruff check core/` → Expected: passes.

- [ ] **Step 6: Commit**

```bash
git add core/f0_sectools_core/auth/graph.py core/tests/test_graph.py
git commit -m "feat(core): add async Microsoft Graph client (token, paging, retry)"
```

---

# Phase 3 — Microsoft Defender & Entra ID MCP servers

> Phase 3 is specified for the next working session. It depends on Phase 2's
> `GraphClient`, `Finding`, `PlatformConfig`, and `redact_obj`.

### Task 7: Defender server scaffold + `.env.defender.example`

**Files:**
- Create: `servers/defender-mcp/pyproject.toml`, `servers/defender-mcp/f0_defender_mcp/__init__.py`, `servers/defender-mcp/.env.defender.example`
- Modify: root `pyproject.toml` is already `members = ["core", "servers/*"]` (no change needed).

**Interfaces:**
- Produces: an installable `f0-defender-mcp` package depending on `f0-sectools-core` and `mcp>=1.0`.

- [ ] **Step 1: Write `pyproject.toml`**

```toml
# servers/defender-mcp/pyproject.toml
[project]
name = "f0-defender-mcp"
version = "0.0.1"
requires-python = ">=3.11"
license = { text = "Apache-2.0" }
dependencies = ["f0-sectools-core", "mcp>=1.0", "httpx>=0.27"]

[tool.uv.sources]
f0-sectools-core = { workspace = true }

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["f0_defender_mcp"]
```

- [ ] **Step 2: Write `.env.defender.example`** (documents the recommended permissions)

```bash
# servers/defender-mcp/.env.defender.example  → copy to .env.defender (gitignored)
DEFENDER_TENANT_ID=
DEFENDER_CLIENT_ID=
DEFENDER_CLIENT_SECRET=
DEFENDER_VERIFY_TLS=true
# Required Graph application permissions (admin consent), read-only:
#   SecurityIncident.Read.All   – incidents (correlated alert groups)
#   SecurityAlert.Read.All      – alerts_v2 (Defender XDR alerts)
#   ThreatHunting.Read.All      – advanced hunting (runHuntingQuery, 30d events)
#   SecurityEvents.Read.All     – legacy secure score / control profiles (fallback)
# Licensing: incidents/hunting require Microsoft Defender licensing.
```

- [ ] **Step 3: Sync + commit**

Run: `uv sync --extra dev` → Expected: `f0-defender-mcp` resolved as workspace member.

```bash
git add servers/defender-mcp/ uv.lock
git commit -m "feat(defender): scaffold defender-mcp package and env example"
```

### Task 8: Defender read tools (incidents, alerts, secure score, hunting)

**Files:**
- Create: `servers/defender-mcp/f0_defender_mcp/tools.py`, `servers/defender-mcp/f0_defender_mcp/server.py`
- Test: `servers/defender-mcp/tests/test_tools.py`

**Interfaces:**
- Consumes: `GraphClient`, `Finding`, `Severity`, `EntityKind`, `FindingType`, `redact_obj`, `PlatformConfig`.
- Produces these tool functions (each `async`, each returns `list[Finding]`; each catches `GraphError(403)` and returns `[Finding.permission_missing(...)]`):
  - `get_secure_score(gc: GraphClient) -> list[Finding]` — GET `/security/secureScores` (top 1), maps to a `posture` finding (current/max score, percentage).
  - `list_incidents(gc, severity_min: str = "medium", limit: int = 25) -> list[Finding]` — GET `/security/incidents?$top={limit}&$filter=severity ge '{severity_min}'` style (client-side filter if needed), maps each to an `incident` finding.
  - `list_alerts(gc, severity_min: str = "high", limit: int = 25) -> list[Finding]` — GET `/security/alerts_v2`, maps to `alert` findings with MITRE technique references.
  - `run_hunting_query(gc, kql: str) -> list[Finding]` — POST `/security/runHuntingQuery` `{"Query": kql}`, returns `hunt_result` findings (bounded to first 50 rows).

Defender→findings severity mapping: Graph `informational|low|medium|high` → `Severity.info|low|medium|high`; treat `high` incidents flagged multi-stage as candidate `critical` only if `>3` alerts.

- [ ] **Step 1: Write the failing test for `list_incidents` (mocked Graph)**

```python
# servers/defender-mcp/tests/test_tools.py
import httpx, pytest, respx
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_defender_mcp.tools import list_incidents

CFG = PlatformConfig(tenant_id="t", client_id="c", client_secret="s")

def _token(mock):
    mock.post("https://login.microsoftonline.com/t/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600}))

@pytest.mark.asyncio
@respx.mock
async def test_list_incidents_maps_to_findings():
    _token(respx)
    respx.get(url__startswith="https://graph.microsoft.com/v1.0/security/incidents").mock(
        return_value=httpx.Response(200, json={"value": [
            {"id": "42", "displayName": "Multi-stage incident", "severity": "high",
             "status": "active", "alerts": [{}, {}, {}, {}]}]}))
    async with GraphClient(CFG) as gc:
        findings = await list_incidents(gc)
    assert findings[0].finding_type.value == "incident"
    assert "Multi-stage incident" in findings[0].title

@pytest.mark.asyncio
@respx.mock
async def test_list_incidents_403_returns_permission_finding():
    _token(respx)
    respx.get(url__startswith="https://graph.microsoft.com/v1.0/security/incidents").mock(
        return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}}))
    async with GraphClient(CFG) as gc:
        findings = await list_incidents(gc)
    assert findings[0].finding_type.value == "posture"
    assert "SecurityIncident.Read.All" in findings[0].title
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest servers/defender-mcp/tests/test_tools.py -v` → Expected: FAIL (module missing).

- [ ] **Step 3: Implement `tools.py`** (full `list_incidents` shown; others follow the same shape)

```python
# servers/defender-mcp/f0_defender_mcp/tools.py
"""Defender XDR read tools → findings. Read-only; 403 degrades to a posture finding."""
from __future__ import annotations
from f0_sectools_core.auth.graph import GraphClient, GraphError
from f0_sectools_core.schema.findings import (
    Finding, Entity, Evidence, RecommendedAction, Severity, EntityKind, FindingType,
)

_SEV = {"informational": Severity.info, "low": Severity.low,
        "medium": Severity.medium, "high": Severity.high}


async def list_incidents(gc: GraphClient, severity_min: str = "medium", limit: int = 25) -> list[Finding]:
    try:
        raw = await gc.get_all("/security/incidents", params={"$top": limit})
    except GraphError as e:
        if e.status == 403:
            return [Finding.permission_missing("defender", "SecurityIncident.Read.All", "Defender incidents")]
        raise
    findings: list[Finding] = []
    for inc in raw:
        alerts = inc.get("alerts") or []
        sev = _SEV.get(str(inc.get("severity", "medium")).lower(), Severity.medium)
        if sev == Severity.high and len(alerts) > 3:
            sev = Severity.critical
        findings.append(Finding(
            source="defender",
            finding_type=FindingType.incident,
            severity=sev,
            title=inc.get("displayName", "Defender incident"),
            entity=Entity(kind=EntityKind.tenant, id=str(inc.get("id", "unknown"))),
            evidence=[Evidence(key="alerts", value=str(len(alerts))),
                      Evidence(key="status", value=str(inc.get("status", "")))],
            recommended_action=RecommendedAction(summary="Investigate incident in Defender portal"),
        ))
    return findings
# get_secure_score, list_alerts, run_hunting_query follow the same structure:
# call gc / map fields / catch GraphError(403) -> Finding.permission_missing(...).
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest servers/defender-mcp/tests/test_tools.py -v` → Expected: 2 passed.

- [ ] **Step 5: Register tools in `server.py`** (MCP stdio server)

```python
# servers/defender-mcp/f0_defender_mcp/server.py
"""Defender MCP server (stdio). Read-only tools over Microsoft Graph."""
from __future__ import annotations
from mcp.server.fastmcp import FastMCP
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from . import tools

mcp = FastMCP("f0-defender")


@mcp.tool()
async def list_incidents(severity_min: str = "medium", limit: int = 25) -> list[dict]:
    """List Defender XDR incidents (correlated alert groups). severity_min: info|low|medium|high|critical."""
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return [f.model_dump() for f in await tools.list_incidents(gc, severity_min, limit)]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Commit**

```bash
git add servers/defender-mcp/
git commit -m "feat(defender): add read tools (incidents, alerts, secure score, hunting)"
```

### Task 9: Entra server scaffold + `.env.entra.example`

**Files:**
- Create: `servers/entra-mcp/pyproject.toml`, `servers/entra-mcp/f0_entra_mcp/__init__.py`, `servers/entra-mcp/.env.entra.example`

**Interfaces:**
- Produces: installable `f0-entra-mcp` (mirrors Task 7's pyproject shape with package `f0_entra_mcp`).

- [ ] **Step 1: Write `.env.entra.example`**

```bash
# servers/entra-mcp/.env.entra.example  → copy to .env.entra (gitignored)
ENTRA_TENANT_ID=
ENTRA_CLIENT_ID=
ENTRA_CLIENT_SECRET=
ENTRA_VERIFY_TLS=true
# Required Graph application permissions (admin consent), read-only:
#   Directory.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All,
#   RoleManagement.Read.Directory      – existing
#   AuditLog.Read.All                  – sign-in + directory audit logs
#   IdentityRiskyUser.Read.All         – Identity Protection risky users (P2)
#   IdentityRiskEvent.Read.All         – risk detections (P2)
# Optional (tier 2): Application.Read.All, IdentityRiskyServicePrincipal.Read.All,
#   Reports.Read.All, Device.Read.All, DeviceManagementManagedDevices.Read.All
```

- [ ] **Step 2: Write `pyproject.toml`** (same as Task 7 with name `f0-entra-mcp`, package `f0_entra_mcp`).

- [ ] **Step 3: Sync + commit**

```bash
uv sync --extra dev
git add servers/entra-mcp/ uv.lock
git commit -m "feat(entra): scaffold entra-mcp package and env example"
```

### Task 10: Entra read tools (risky users, risk detections, conditional access, privileged roles)

**Files:**
- Create: `servers/entra-mcp/f0_entra_mcp/tools.py`, `servers/entra-mcp/f0_entra_mcp/server.py`
- Test: `servers/entra-mcp/tests/test_tools.py`

**Interfaces:**
- Consumes: `GraphClient`, `Finding`, schema enums, `PlatformConfig`.
- Produces (each `async`, returns `list[Finding]`, 403 → `Finding.permission_missing`):
  - `list_risky_users(gc, limit: int = 25) -> list[Finding]` — GET `/identityProtection/riskyUsers` → `risk` findings (entity kind `user`, severity from `riskLevel`). 403 → permission `IdentityRiskyUser.Read.All`.
  - `list_risk_detections(gc, limit: int = 25) -> list[Finding]` — GET `/identityProtection/riskDetections` → `risk` findings. 403 → `IdentityRiskEvent.Read.All`.
  - `list_conditional_access_policies(gc) -> list[Finding]` — GET `/identity/conditionalAccess/policies` → `misconfig`/`posture` findings (flag disabled policies, missing MFA). 403 → `Policy.Read.All`.
  - `list_privileged_role_assignments(gc) -> list[Finding]` — GET `/roleManagement/directory/roleAssignments?$expand=principal,roleDefinition` → `posture` findings for privileged roles (Global Admin etc.). 403 → `RoleManagement.Read.Directory`.

Severity mapping for risk: `low|medium|high` → `Severity.low|medium|high`; `none` → `info`.

- [ ] **Step 1: Write the failing test for `list_risky_users`** (mirror Task 8's two-test pattern: maps-to-findings + 403-returns-permission). Full test code:

```python
# servers/entra-mcp/tests/test_tools.py
import httpx, pytest, respx
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_entra_mcp.tools import list_risky_users

CFG = PlatformConfig(tenant_id="t", client_id="c", client_secret="s")

def _token(mock):
    mock.post("https://login.microsoftonline.com/t/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600}))

@pytest.mark.asyncio
@respx.mock
async def test_list_risky_users_maps_to_findings():
    _token(respx)
    respx.get(url__startswith="https://graph.microsoft.com/v1.0/identityProtection/riskyUsers").mock(
        return_value=httpx.Response(200, json={"value": [
            {"id": "u1", "userPrincipalName": "ada@corp.com", "riskLevel": "high", "riskState": "atRisk"}]}))
    async with GraphClient(CFG) as gc:
        findings = await list_risky_users(gc)
    assert findings[0].finding_type.value == "risk"
    assert findings[0].severity.value == "high"
    assert findings[0].entity.name == "ada@corp.com"

@pytest.mark.asyncio
@respx.mock
async def test_list_risky_users_403_returns_permission_finding():
    _token(respx)
    respx.get(url__startswith="https://graph.microsoft.com/v1.0/identityProtection/riskyUsers").mock(
        return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}}))
    async with GraphClient(CFG) as gc:
        findings = await list_risky_users(gc)
    assert "IdentityRiskyUser.Read.All" in findings[0].title
```

- [ ] **Step 2: Run to verify it fails.** Run: `uv run pytest servers/entra-mcp/tests/test_tools.py -v` → FAIL.

- [ ] **Step 3: Implement `list_risky_users`** (others follow the same shape):

```python
# servers/entra-mcp/f0_entra_mcp/tools.py
"""Entra ID read tools → findings. Read-only; 403 degrades to a posture finding."""
from __future__ import annotations
from f0_sectools_core.auth.graph import GraphClient, GraphError
from f0_sectools_core.schema.findings import (
    Finding, Entity, RecommendedAction, Severity, EntityKind, FindingType,
)

_RISK = {"none": Severity.info, "low": Severity.low, "medium": Severity.medium, "high": Severity.high}


async def list_risky_users(gc: GraphClient, limit: int = 25) -> list[Finding]:
    try:
        raw = await gc.get_all("/identityProtection/riskyUsers", params={"$top": limit})
    except GraphError as e:
        if e.status == 403:
            return [Finding.permission_missing("entra", "IdentityRiskyUser.Read.All", "Entra risky users")]
        raise
    out: list[Finding] = []
    for u in raw:
        out.append(Finding(
            source="entra",
            finding_type=FindingType.risk,
            severity=_RISK.get(str(u.get("riskLevel", "none")).lower(), Severity.info),
            title=f"Risky user: {u.get('userPrincipalName', u.get('id', 'unknown'))}",
            entity=Entity(kind=EntityKind.user, id=str(u.get("id", "")), name=u.get("userPrincipalName")),
            recommended_action=RecommendedAction(summary="Review sign-in risk; consider risk-based CA / password reset"),
        ))
    return out
```

- [ ] **Step 4: Run to verify it passes.** Run: `uv run pytest servers/entra-mcp/tests/test_tools.py -v` → 2 passed.

- [ ] **Step 5: Register tools in `server.py`** (FastMCP, mirroring Task 8 Step 5 with the Entra tools and `PlatformConfig.from_env("ENTRA")`).

- [ ] **Step 6: Commit**

```bash
git add servers/entra-mcp/
git commit -m "feat(entra): add read tools (risky users, risk detections, CA, privileged roles)"
```

### Task 11: Small-model eval task sets

**Files:**
- Create: `evals/defender/tasks.yaml`, `evals/entra/tasks.yaml`

**Interfaces:**
- Produces: YAML task sets (natural-language prompt → expected tool name + key args) the eval harness will use to measure callability. The harness itself is a later plan; these task sets define the bar now.

- [ ] **Step 1: Write `evals/defender/tasks.yaml`**

```yaml
# Each task: a natural-language ask, the tool a small model should call, and key args.
- prompt: "Show me the active high-severity incidents."
  expect_tool: list_incidents
  expect_args: { severity_min: high }
- prompt: "What's our Microsoft secure score?"
  expect_tool: get_secure_score
  expect_args: {}
- prompt: "Hunt for PowerShell downloads in the last day."
  expect_tool: run_hunting_query
  expect_args_contains: { kql: "DeviceProcessEvents" }
```

- [ ] **Step 2: Write `evals/entra/tasks.yaml`**

```yaml
- prompt: "Which users are flagged as risky right now?"
  expect_tool: list_risky_users
  expect_args: {}
- prompt: "List conditional access policies that are disabled."
  expect_tool: list_conditional_access_policies
  expect_args: {}
- prompt: "Who has privileged directory roles?"
  expect_tool: list_privileged_role_assignments
  expect_args: {}
```

- [ ] **Step 3: Commit**

```bash
git add evals/
git commit -m "feat(evals): add Defender and Entra small-model callability task sets"
```

---

## Self-Review notes

- **Spec coverage:** Phase 1 (workspace) and Phase 2 (core: schema, redaction, gating, config, Graph client) are fully TDD'd. Phase 3 covers both Microsoft servers + permission-aware degradation + eval task sets, satisfying "first implementations for MS Defender and Entra ID" and the permission recommendations.
- **Type consistency:** `Finding`, `Entity`, `Evidence`, `RecommendedAction`, `Severity`, `EntityKind`, `FindingType`, `Finding.permission_missing`, `GraphClient.get/get_all/post`, `PlatformConfig.from_env`, `GatedAction.execute` are referenced with identical signatures across tasks.
- **Read-only:** no server registers a gated write; `GatedAction` is built and tested but unused by servers, honoring the read-only-by-default constraint.
- **Out of scope (future plans):** the eval *harness* runtime, persona renderers wired into servers, additional platforms, and any gated write actions.
