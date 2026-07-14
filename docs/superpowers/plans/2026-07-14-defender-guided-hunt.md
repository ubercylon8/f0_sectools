# Guided Defender Hunt (`hunt`) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a guided `hunt(category, indicator, time_window_hours)` tool to the Defender server that builds vetted KQL server-side, so small models stop guessing field names. Keep `run_hunting_query` for custom KQL (disambiguated).

**Architecture:** Extract the POST+render path from `run_hunting_query` into `_execute_hunt`; `hunt` sanitizes inputs, builds KQL from four category templates, and calls `_execute_hunt`. Defender 6→7 tools.

**Tech Stack:** Python, `respx` (captures the POSTed `Query` body), MCP `FastMCP`.

## Global Constraints

From the spec (`docs/superpowers/specs/2026-07-14-defender-guided-hunt-design.md`):

- Read-only; no gating/redaction/schema changes; every failure a finding, never an exception.
- Small-model-safe: flat scalar args, one short closed enum (`category` = network|process|logon|email), bounded output. Defender stays ≤8 tools (→7).
- **Indicator sanitization is mandatory** (KQL-injection guard): whitelist `^[A-Za-z0-9._:@/\\-]{1,120}$`, reject (never strip-and-run).
- Indicator **required** for network/process; **optional** for logon/email.
- `time_window_hours` clamped to `[1, 720]` via `clamp_limit(..., default=24, maximum=720)`.
- Templates use `Timestamp` (documented Defender field) — **live-validation-pending** (`Timestamp` vs `TimeGenerated`).
- **Disambiguation:** `hunt` = default for NL hunts; `run_hunting_query` = custom KQL only. An eval task guards the boundary.
- Tool count **35→36** (34 read + 2 gated); **scorecard stays 34** (hunt pending its eval pass — do not claim it was benchmarked).

## File Structure

- `servers/defender-mcp/f0_defender_mcp/tools.py` — `import re`; hunt constants; `_execute_hunt`; thin `run_hunting_query`; `_hunt_finding`, `_build_hunt_kql`, `hunt`.
- `servers/defender-mcp/f0_defender_mcp/server.py` — enrich `run_hunting_query` docstring; register `hunt`.
- `servers/defender-mcp/tests/test_tools.py` — hunt tests.
- `skills/defender/threat-hunt/SKILL.md` — make `hunt` primary.
- `evals/defender/tasks.yaml` — re-route hunting tasks.
- `evals/test_combined.py` — counts 35→36 tools, 54→57 tasks.
- `README.md`, `docs/user-guide/README.md`, `CLAUDE.md`, `CHANGELOG.md` — counts + defender hunt mention.

---

### Task 1: `hunt` tool + refactor + registration + tests

**Files:**
- Modify: `servers/defender-mcp/f0_defender_mcp/tools.py`, `servers/defender-mcp/f0_defender_mcp/server.py`, `servers/defender-mcp/tests/test_tools.py`

**Interfaces:**
- Produces: `hunt(gc, category, indicator, time_window_hours) -> list[Finding]`; the `hunt` MCP tool. Reuses `clamp_limit` (already imported in this file).

- [ ] **Step 1: Write the failing tests** — in `servers/defender-mcp/tests/test_tools.py`, add `hunt` to the `from f0_defender_mcp.tools import (...)` block, ensure `import json` is present at the top (add it if not), then append:

```python
@pytest.mark.asyncio
async def test_hunt_network_builds_correct_kql():
    with respx.mock as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(200, json={"results": [{"DeviceName": "web-01"}]})
        )
        async with GraphClient(CFG) as gc:
            findings = await hunt(gc, "network", "evil.com", 24)
    body = json.loads(route.calls.last.request.content)
    assert "DeviceNetworkEvents" in body["Query"]
    assert 'RemoteUrl contains "evil.com"' in body["Query"]
    assert "ago(24h)" in body["Query"]
    assert findings[0].finding_type.value == "hunt_result"


@pytest.mark.asyncio
async def test_hunt_process_builds_correct_kql():
    with respx.mock as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        async with GraphClient(CFG) as gc:
            await hunt(gc, "process", "powershell.exe")
    body = json.loads(route.calls.last.request.content)
    assert "DeviceProcessEvents" in body["Query"]
    assert 'FileName has "powershell.exe"' in body["Query"]


@pytest.mark.asyncio
async def test_hunt_logon_without_indicator_omits_account_filter():
    with respx.mock as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        async with GraphClient(CFG) as gc:
            await hunt(gc, "logon")
    body = json.loads(route.calls.last.request.content)
    assert "DeviceLogonEvents" in body["Query"]
    assert "AccountName has" not in body["Query"]


@pytest.mark.asyncio
async def test_hunt_email_with_indicator_adds_filter():
    with respx.mock as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        async with GraphClient(CFG) as gc:
            await hunt(gc, "email", "bad@sender.com")
    body = json.loads(route.calls.last.request.content)
    assert "EmailEvents" in body["Query"]
    assert 'SenderFromAddress has "bad@sender.com"' in body["Query"]


@pytest.mark.asyncio
async def test_hunt_network_requires_indicator_no_call():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery")
        async with GraphClient(CFG) as gc:
            findings = await hunt(gc, "network", "")
    assert not route.called
    assert "needs an indicator" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_hunt_invalid_indicator_rejected_no_call():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery")
        async with GraphClient(CFG) as gc:
            findings = await hunt(gc, "network", 'evil".io')
    assert not route.called
    assert "unsupported characters" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_hunt_unknown_category_no_call():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery")
        async with GraphClient(CFG) as gc:
            findings = await hunt(gc, "dns", "evil.com")
    assert not route.called
    assert "unknown hunt category" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_hunt_clamps_time_window():
    with respx.mock as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        async with GraphClient(CFG) as gc:
            await hunt(gc, "network", "evil.com", 99999)
    body = json.loads(route.calls.last.request.content)
    assert "ago(720h)" in body["Query"]
```

- [ ] **Step 2: Run — expect failure** (`ImportError: cannot import name 'hunt'`)

Run: `uv run pytest servers/defender-mcp/tests/test_tools.py -k hunt -q`
Expected: FAIL (import error / hunt undefined).

- [ ] **Step 3: Add `import re`** — in `servers/defender-mcp/f0_defender_mcp/tools.py`, change the top import line `from typing import Any` block to also import `re`. Add at the top of the stdlib imports:

```python
import re
```

- [ ] **Step 4: Add hunt constants + helpers + refactor** — in `servers/defender-mcp/f0_defender_mcp/tools.py`, add these constants near `_MAX_HUNT_ROWS = 50`:

```python
_HUNT_CATEGORIES = ("network", "process", "logon", "email")
_INDICATOR_REQUIRED = frozenset({"network", "process"})
_INDICATOR_RE = re.compile(r"^[A-Za-z0-9._:@/\\-]{1,120}$")
_MAX_HUNT_WINDOW_H = 720
```

Then **replace** the existing `run_hunting_query` function (the whole `async def run_hunting_query(gc: GraphClient, kql: str) -> list[Finding]:` through its closing `]`) with the extracted helper + a thin wrapper + the hunt builder + tool:

```python
async def _execute_hunt(gc: GraphClient, kql: str) -> list[Finding]:
    try:
        resp = await gc.post("/security/runHuntingQuery", {"Query": kql})
    except GraphError as e:
        finding = map_graph_error(e, "defender", "ThreatHunting.Read.All", "advanced hunting")
        if finding:
            return [finding]
        raise
    rows = resp.get("results") or []
    sample = rows[:_MAX_HUNT_ROWS]
    evidence = [Evidence(key=f"row_{i}", value=str(row)) for i, row in enumerate(sample)]
    return [
        Finding(
            source="defender",
            finding_type=FindingType.hunt_result,
            severity=Severity.info,
            title=f"Hunting query returned {len(rows)} row(s)"
            + (f" (showing first {_MAX_HUNT_ROWS})" if len(rows) > _MAX_HUNT_ROWS else ""),
            evidence=evidence,
            recommended_action=RecommendedAction(
                summary="Review the returned rows; refine the query to investigate further."
            ),
        )
    ]


async def run_hunting_query(gc: GraphClient, kql: str) -> list[Finding]:
    return await _execute_hunt(gc, kql)


def _hunt_guidance(title: str, summary: str) -> list[Finding]:
    return [
        Finding(
            source="defender",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=title,
            recommended_action=RecommendedAction(summary=summary),
        )
    ]


def _build_hunt_kql(category: str, ind: str, hours: int) -> str:
    n = _MAX_HUNT_ROWS
    if category == "network":
        return (
            "DeviceNetworkEvents\n"
            f"| where Timestamp > ago({hours}h)\n"
            f'| where RemoteUrl contains "{ind}" or RemoteIP == "{ind}"\n'
            "| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, "
            "InitiatingProcessFileName, ActionType\n"
            f"| take {n}"
        )
    if category == "process":
        return (
            "DeviceProcessEvents\n"
            f"| where Timestamp > ago({hours}h)\n"
            f'| where FileName has "{ind}" or ProcessCommandLine contains "{ind}"\n'
            "| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine\n"
            f"| take {n}"
        )
    if category == "logon":
        acct = f'| where AccountName has "{ind}"\n' if ind else ""
        return (
            "DeviceLogonEvents\n"
            f"| where Timestamp > ago({hours}h)\n"
            '| where ActionType == "LogonFailed"\n'
            f"{acct}"
            "| summarize Failures = count() by AccountName, DeviceName, bin(Timestamp, 1h)\n"
            "| where Failures > 10\n"
            f"| take {n}"
        )
    filt = (
        f'| where SenderFromAddress has "{ind}" or Subject contains "{ind}"\n' if ind else ""
    )
    return (
        "EmailEvents\n"
        f"| where Timestamp > ago({hours}h)\n"
        '| where ThreatTypes has "Phish" or ThreatTypes has "Malware"\n'
        f"{filt}"
        "| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes\n"
        f"| take {n}"
    )


async def hunt(
    gc: GraphClient, category: str, indicator: str = "", time_window_hours: int = 24
) -> list[Finding]:
    cat = category.strip().lower()
    if cat not in _HUNT_CATEGORIES:
        return _hunt_guidance(
            f"Unknown hunt category '{category}'.",
            "Use one of: network, process, logon, email.",
        )
    ind = indicator.strip()
    if cat in _INDICATOR_REQUIRED and not ind:
        return _hunt_guidance(
            f"The {cat} hunt needs an indicator.",
            "network: a domain or IP; process: a name or command-line fragment.",
        )
    if ind and not _INDICATOR_RE.match(ind):
        return _hunt_guidance(
            "Indicator contains unsupported characters.",
            "Use a plain domain, IP, process name, path, or account.",
        )
    hours = clamp_limit(time_window_hours, default=24, maximum=_MAX_HUNT_WINDOW_H)
    kql = _build_hunt_kql(cat, ind, hours)
    return await _execute_hunt(gc, kql)
```

- [ ] **Step 5: Register + enrich in `server.py`** — replace the `run_hunting_query` `@mcp.tool()` docstring's "Common tables…" sentence with a field-aware version, and add the `hunt` tool after it:

Replace this line in `run_hunting_query`'s docstring:
```python
    Common tables: DeviceProcessEvents (processes), SigninLogs or AADSignInEventsBeta
    (sign-ins), DeviceNetworkEvents (network), EmailEvents (email). Always bound
    results with `| take 50`.
```
with:
```python
    For common hunts prefer the `hunt` tool (it builds the KQL for you); use this
    only for a CUSTOM KQL query you provide. Key tables & fields: DeviceNetworkEvents
    (Timestamp, RemoteUrl, RemoteIP, RemotePort), DeviceProcessEvents (Timestamp,
    DeviceName, FileName, ProcessCommandLine, AccountName), DeviceLogonEvents
    (Timestamp, ActionType, AccountName, DeviceName), EmailEvents (Timestamp,
    SenderFromAddress, Subject, ThreatTypes). Always bound results with `| take 50`.
```

Then add, after the `run_hunting_query` tool function:
```python
@mcp.tool()
async def hunt(
    category: str, indicator: str = "", time_window_hours: int = 24
) -> list[dict[str, Any]]:
    """Guided Microsoft Defender hunt — the server builds correct KQL, so you don't have to.

    category: network | process | logon | email.
    indicator: what to look for — a domain/IP (network), a process name or
    command-line fragment (process); optional for logon/email. Prefer this over
    run_hunting_query unless the user gives you custom KQL.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.hunt(gc, category, indicator, time_window_hours))
```

- [ ] **Step 6: Run — expect pass** (new hunt tests + existing defender tests, incl. `test_run_hunting_query_maps` which now exercises the shared `_execute_hunt`)

Run: `uv run pytest servers/defender-mcp/tests/test_tools.py -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add servers/defender-mcp/f0_defender_mcp/tools.py servers/defender-mcp/f0_defender_mcp/server.py \
        servers/defender-mcp/tests/test_tools.py
git commit -m "feat(defender): guided hunt tool (enum category -> server-built KQL)"
```

---

### Task 2: skill, evals, docs, counts (35→36)

**Files:**
- Modify: `skills/defender/threat-hunt/SKILL.md`, `evals/defender/tasks.yaml`, `evals/test_combined.py`, `README.md`, `docs/user-guide/README.md`, `CLAUDE.md`, `CHANGELOG.md`

- [ ] **Step 1: Skill — make `hunt` primary.** In `skills/defender/threat-hunt/SKILL.md`, replace Procedure step 2:
```markdown
2. Pick a starting query. See `references/kql-starters.md` for safe templates by
   table (process, logon, network, email). Always include a `| take N` bound.
3. Call `run_hunting_query` with the KQL.
```
with:
```markdown
2. Call the `hunt` tool with a `category` (network | process | logon | email) and
   an `indicator` (a domain/IP for network, a process name for process; optional
   for logon/email). It builds correct KQL for you — no field-name guessing.
3. Only for a custom query the user provides: call `run_hunting_query` with KQL
   (see `references/kql-starters.md` for vetted templates and field names).
```
Keep the `description` frontmatter unchanged (already ≤60 chars).

- [ ] **Step 2: Evals — re-route hunting tasks.** In `evals/defender/tasks.yaml`, replace the two existing hunting tasks:
```yaml
- prompt: "Hunt for processes that downloaded files using PowerShell in the last day."
  expect_tool: run_hunting_query
  expect_args_contains: { kql: "DeviceProcessEvents" }

- prompt: "Run an advanced hunting query for suspicious sign-ins."
  expect_tool: run_hunting_query
```
with:
```yaml
- prompt: "Hunt for PowerShell process launches in the last day."
  expect_tool: hunt
  expect_args: { category: process }

- prompt: "Check for network connections to evil.com."
  expect_tool: hunt
  expect_args: { category: network }

- prompt: "Any suspicious failed sign-ins?"
  expect_tool: hunt
  expect_args: { category: logon }

- prompt: "Look for phishing emails this week."
  expect_tool: hunt
  expect_args: { category: email }

- prompt: "Run this hunting query: DeviceInfo | take 5"
  expect_tool: run_hunting_query
```

- [ ] **Step 3: Combined-count test.** In `evals/test_combined.py`, bump the hardcoded expected tool count `35`→`36` and task count `54`→`57` (defender gained 1 tool and net +3 tasks). Update any accompanying comment.

- [ ] **Step 4: Docs — current-inventory counts 35→36.**
  - `README.md:24` — `**35 registered tools.**` → `**36 registered tools.**`
  - `README.md:38` (scorecard) — leave the `34`; extend the existing "pending its scorecard pass" note to cover both new tools, e.g. "…the new Tenable `list_vulnerability_assets` and Defender `hunt` tools are pending their scorecard pass."
  - `docs/user-guide/README.md` Defender matrix row — append `, guided hunt` to its tool list.
  - `CLAUDE.md` — Defender read-tools description: mention the guided `hunt` tool.

- [ ] **Step 5: CHANGELOG** — under the existing `## [Unreleased]` → `### Added`, add:
```markdown
- **Defender `hunt`** — guided advanced-hunting tool (category + indicator →
  server-built KQL) so small models stop guessing field names; `run_hunting_query`
  remains for custom KQL.
```

- [ ] **Step 6: Verify — counts, skill, full gates.**
```bash
cd /home/jimx/F0RT1KA/sec-tools
grep -n "35 registered" README.md      # expect: none
grep -n "36 registered" README.md      # expect: 1
uv run python skills/test_skills_valid.py 2>/dev/null || uv run pytest skills/test_skills_valid.py -q
uv run pytest -q && uv run ruff check . && uv run mypy .
```
Expected: no `35 registered`; skills valid; full suite green (incl. `evals/test_combined.py` and `evals/test_eval_coverage.py`, which now sees `hunt` covered); ruff + mypy clean.

- [ ] **Step 7: Commit**
```bash
git add skills/defender/threat-hunt/SKILL.md evals/defender/tasks.yaml evals/test_combined.py \
        README.md docs/user-guide/README.md CLAUDE.md CHANGELOG.md
git commit -m "docs+evals: register hunt tool, re-route hunting evals (35->36 tools)"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** C1/C2→Task 1 Steps 3-4; C3→Task 1 Step 5; C4→Task 1 Step 5; C5→Task 2 Step 1; docs/evals/counts→Task 2. Disambiguation → Task 1 Step 5 (descriptions) + Task 2 Step 2 (explicit-KQL eval task).
- **Placeholder scan:** all code is verbatim; no TODO. The `[| where …]` optional lines from the spec are materialized as concrete `if ind else ""` branches.
- **Type/name consistency:** `hunt` signature identical across tools.py, server.py, tests, eval `expect_tool`; `_execute_hunt` used by both `run_hunting_query` and `hunt`; `clamp_limit` reused for the window (already imported).
- **Count discipline:** current-inventory 35→36; scorecard stays 34 with the pending-note extended (no fabricated benchmark).
- **Injection guard:** whitelist regex rejects (no strip-and-run); tests cover the reject path with no POST made.
- **Live-validation seam:** `Timestamp` is used per docs; flagged for pi confirmation (`Timestamp` vs `TimeGenerated`).
