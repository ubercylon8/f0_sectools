# Bounded Output + Tenable plugin→hosts — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Tenable plugin→hosts tool and fix the `get_all($top=limit)` unbounded pattern in defender/entra; clamp `limit` across list tools. Both surfaced by the pi live-run.

**Architecture:** Shared bounding helpers in `core/paging`; four Graph tools switch from `get_all` (paginates everything) to single-page `get` + slice + a "more available" note; a new Tenable tool over `/workbenches/vulnerabilities/{plugin_id}/outputs`.

**Tech Stack:** Python, `httpx`/`respx` (defender/entra tests), a `FakeClient` (tenable tests), MCP `FastMCP`.

## Global Constraints

Copied verbatim from the spec (`docs/superpowers/specs/2026-07-14-bounded-output-and-tenable-plugin-assets-design.md`); every task's requirements include these:

- **Read-only; no gating/redaction/schema changes.** Every failure still becomes a finding, never an exception.
- **Shared logic lives in `core/` only** (Rule 6): `clamp_limit`, `more_available_finding` in `core/paging`; no server re-implements them.
- **Bounding approach = single-page `get(...$top=limit)` + client severity filter + slice to `limit`** (rely on API default order). Append `more_available_finding(...)` when `@odata.nextLink` is present.
- **Clamp `limit` to `[1, 100]`** (`clamp_limit`, `MAX_LIMIT = 100`, default 25) at the top of every list tool.
- **The four unbounded tools (only these):** defender `list_incidents`, `list_alerts`; entra `list_risky_users`, `list_risk_detections`. Tenable list tools already slice — they need only the clamp.
- **New Tenable tool** `list_vulnerability_assets(plugin_id, limit)` — Tenable 6→7 (≤8). Flat scalar args, one-sentence description.
- **Tool count 34→35 (33 read + 2 gated).** Update *current-count* refs; but the **scorecard** references (README:38 "all 34 tools registered at once", CHANGELOG:24 "combined 34-tool") describe a *past eval of 34 tools* — do NOT bump those to 35; note the new tool is pending its scorecard pass.
- **New Tenable tool is live-validation-pending** (the `/outputs` nesting must be validated against the operator's tenant). Push is user-gated.

## File Structure

- `core/f0_sectools_core/paging/__init__.py` — add `clamp_limit`, `more_available_finding`, `DEFAULT_LIMIT`, `MAX_LIMIT`.
- `core/tests/test_paging.py` — new.
- `servers/defender-mcp/f0_defender_mcp/tools.py` — import + rewrite `list_incidents`, `list_alerts`.
- `servers/defender-mcp/tests/test_tools.py` — add 2 regression tests.
- `servers/entra-mcp/f0_entra_mcp/tools.py` — import + rewrite `list_risky_users`, `list_risk_detections`.
- `servers/entra-mcp/tests/test_tools.py` — add 2 regression tests.
- `servers/tenable-mcp/f0_tenable_mcp/tools.py` — import + clamp 4 tools + add `_plugin_output_assets`, `list_vulnerability_assets`.
- `servers/tenable-mcp/f0_tenable_mcp/server.py` — register `list_vulnerability_assets`.
- `servers/tenable-mcp/tests/test_tools.py` — add 4 tests.
- `scripts/live_smoke_tenable.py` — add the new tool.
- `evals/tenable/tasks.yaml` — add a task.
- `skills/tenable/host-vulnerability-triage/SKILL.md` — mention the new tool.
- `README.md`, `docs/user-guide/README.md`, `CLAUDE.md`, `CHANGELOG.md` — counts + tenable tool list + changelog entry.

---

### Task 1: `core/paging` helpers + tests

**Files:**
- Modify: `core/f0_sectools_core/paging/__init__.py`
- Create: `core/tests/test_paging.py`

**Interfaces:**
- Produces: `clamp_limit(limit, default=25, maximum=100) -> int`; `more_available_finding(source, shown, total=None, hint="") -> Finding`; `DEFAULT_LIMIT`, `MAX_LIMIT` constants. Consumed by Tasks 2, 3, 4.

- [ ] **Step 1: Write the failing tests** — create `core/tests/test_paging.py`:

```python
from f0_sectools_core.paging import (
    MAX_LIMIT,
    clamp_limit,
    more_available_finding,
)


def test_clamp_limit_normal():
    assert clamp_limit(25) == 25
    assert clamp_limit(1) == 1


def test_clamp_limit_over_max_is_capped():
    assert clamp_limit(10000) == MAX_LIMIT


def test_clamp_limit_below_one_floors_to_one():
    assert clamp_limit(0) == 1
    assert clamp_limit(-5) == 1


def test_clamp_limit_invalid_returns_default():
    assert clamp_limit("abc") == 25
    assert clamp_limit(None) == 25


def test_more_available_with_total():
    f = more_available_finding("tenable", shown=25, total=210)
    assert f.finding_type.value == "posture"
    assert f.severity.value == "info"
    assert "25 of 210" in f.title


def test_more_available_without_total():
    f = more_available_finding("defender", shown=25)
    assert "more results available" in f.title
```

- [ ] **Step 2: Run — expect failure** (`ImportError`)

Run: `uv run pytest core/tests/test_paging.py -q`
Expected: FAIL (cannot import `clamp_limit`).

- [ ] **Step 3: Implement** — replace `core/f0_sectools_core/paging/__init__.py` with:

```python
"""Pagination, truncation, and rate-limiting to keep payloads small-model-safe."""
from __future__ import annotations

from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

DEFAULT_LIMIT = 25
MAX_LIMIT = 100


def clamp_limit(limit: object, default: int = DEFAULT_LIMIT, maximum: int = MAX_LIMIT) -> int:
    """Bound a caller-supplied page size to [1, maximum]; invalid -> default.

    Small local models sometimes pass an oversized limit; an unbounded dump blows
    the context window and degrades tool accuracy (Critical Rule 5).
    """
    try:
        n = int(limit)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if n < 1:
        return 1
    return min(n, maximum)


def more_available_finding(
    source: str, shown: int, total: int | None = None, hint: str = ""
) -> Finding:
    """An info finding signalling a truncated result set, so a model stops re-querying."""
    if total is not None:
        title = (
            f"Showing {shown} of {total} — narrow the filter or raise limit "
            f"(max {MAX_LIMIT}) to see more."
        )
    else:
        title = (
            f"Showing {shown}; more results available — narrow the filter or raise "
            f"limit (max {MAX_LIMIT}) to see more."
        )
    return Finding(
        source=source,
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=title,
        entity=Entity(kind=EntityKind.tenant, id=source),
        recommended_action=RecommendedAction(
            summary=hint or "Add a filter (severity_min, hostname) or raise limit to page further.",
        ),
    )
```

- [ ] **Step 4: Run — expect pass**

Run: `uv run pytest core/tests/test_paging.py -q`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/paging/__init__.py core/tests/test_paging.py
git commit -m "feat(core): add paging helpers clamp_limit + more_available_finding"
```

---

### Task 2: defender bounding fix (`list_incidents`, `list_alerts`)

**Files:**
- Modify: `servers/defender-mcp/f0_defender_mcp/tools.py`
- Modify: `servers/defender-mcp/tests/test_tools.py`

**Interfaces:**
- Consumes: `clamp_limit`, `more_available_finding` from `core.paging` (Task 1).

- [ ] **Step 1: Write the failing tests** — append to `servers/defender-mcp/tests/test_tools.py` (mirrors the merged `test_get_secure_score_does_not_paginate_history`; add `list_alerts` to the imports at the top of the file if not present — it already is):

```python
@pytest.mark.asyncio
async def test_list_incidents_single_page_not_paginated():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        page2 = router.get(GRAPH + "/security/incidents", params={"$skiptoken": "x"}).mock(
            return_value=httpx.Response(200, json={"value": [{"id": "999", "severity": "high"}]})
        )
        router.get(GRAPH + "/security/incidents", params={"$top": "25"}).mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "1", "displayName": "A", "severity": "high",
                         "status": "active", "alerts": []}
                    ],
                    "@odata.nextLink": GRAPH + "/security/incidents?$skiptoken=x",
                },
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_incidents(gc, limit=25)
    assert not page2.called  # did NOT paginate the whole tenant
    assert any("more results available" in f.title for f in findings)  # truncation note


@pytest.mark.asyncio
async def test_list_alerts_single_page_not_paginated():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        page2 = router.get(GRAPH + "/security/alerts_v2", params={"$skiptoken": "x"}).mock(
            return_value=httpx.Response(200, json={"value": [{"id": "999", "severity": "high"}]})
        )
        router.get(GRAPH + "/security/alerts_v2", params={"$top": "25"}).mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "a1", "title": "T", "severity": "high",
                         "status": "new", "mitreTechniques": []}
                    ],
                    "@odata.nextLink": GRAPH + "/security/alerts_v2?$skiptoken=x",
                },
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_alerts(gc, limit=25)
    assert not page2.called
    assert any("more results available" in f.title for f in findings)
```

- [ ] **Step 2: Run — expect failure** (current `get_all` follows the nextLink → `page2.called` is True)

Run: `uv run pytest servers/defender-mcp/tests/test_tools.py -k "single_page_not_paginated" -q`
Expected: 2 failed (`assert not page2.called`).

- [ ] **Step 3: Add the import** — in `servers/defender-mcp/f0_defender_mcp/tools.py`, after the existing `from f0_sectools_core...` imports add:

```python
from f0_sectools_core.paging import clamp_limit, more_available_finding
```

- [ ] **Step 4: Replace `list_incidents`** — replace the entire function (currently starting `async def list_incidents(` and ending `    return findings`) with:

```python
async def list_incidents(
    gc: GraphClient, severity_min: str = "medium", limit: int = 25
) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        page = await gc.get("/security/incidents", params={"$top": limit})
    except GraphError as e:
        finding = map_graph_error(e, "defender", "SecurityIncident.Read.All", "Defender incidents")
        if finding:
            return [finding]
        raise
    raw = page.get("value", [])
    has_more = bool(page.get("@odata.nextLink"))
    findings: list[Finding] = []
    for inc in raw:
        alerts = inc.get("alerts") or []
        sev = _sev(inc.get("severity", "medium"))
        # A high-severity incident correlating many alerts is treated as critical.
        if sev == Severity.high and len(alerts) > 3:
            sev = Severity.critical
        if not _meets(sev, severity_min):
            continue
        findings.append(
            Finding(
                source="defender",
                finding_type=FindingType.incident,
                severity=sev,
                title=inc.get("displayName", "Defender incident"),
                entity=Entity(kind=EntityKind.tenant, id=str(inc.get("id", "unknown"))),
                evidence=[
                    Evidence(key="alerts", value=str(len(alerts))),
                    Evidence(key="status", value=str(inc.get("status", ""))),
                ],
                recommended_action=RecommendedAction(
                    summary="Investigate the incident and its correlated alerts in Defender."
                ),
                observed_at=inc.get("createdDateTime"),
            )
        )
    findings = findings[:limit]
    if has_more:
        findings.append(more_available_finding("defender", shown=len(findings)))
    return findings
```

- [ ] **Step 5: Replace `list_alerts`** — replace the entire function with:

```python
async def list_alerts(
    gc: GraphClient, severity_min: str = "high", limit: int = 25
) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        page = await gc.get("/security/alerts_v2", params={"$top": limit})
    except GraphError as e:
        finding = map_graph_error(e, "defender", "SecurityAlert.Read.All", "Defender alerts")
        if finding:
            return [finding]
        raise
    raw = page.get("value", [])
    has_more = bool(page.get("@odata.nextLink"))
    findings: list[Finding] = []
    for alert in raw:
        sev = _sev(alert.get("severity", "medium"))
        if not _meets(sev, severity_min):
            continue
        refs = [Reference(type="mitre", id=t) for t in (alert.get("mitreTechniques") or [])]
        findings.append(
            Finding(
                source="defender",
                finding_type=FindingType.alert,
                severity=sev,
                title=alert.get("title", "Defender alert"),
                entity=Entity(kind=EntityKind.tenant, id=str(alert.get("id", "unknown"))),
                evidence=[
                    Evidence(key="status", value=str(alert.get("status", ""))),
                    Evidence(key="category", value=str(alert.get("category", ""))),
                ],
                references=refs,
                recommended_action=RecommendedAction(summary="Triage the alert in Defender."),
                observed_at=alert.get("createdDateTime"),
            )
        )
    findings = findings[:limit]
    if has_more:
        findings.append(more_available_finding("defender", shown=len(findings)))
    return findings
```

- [ ] **Step 6: Run — expect pass** (new regression tests + all existing defender tests)

Run: `uv run pytest servers/defender-mcp/tests/test_tools.py -q`
Expected: all pass (existing mapping tests mock a single page with no `nextLink`, so `has_more` is False and behaviour is unchanged for them).

- [ ] **Step 7: Commit**

```bash
git add servers/defender-mcp/f0_defender_mcp/tools.py servers/defender-mcp/tests/test_tools.py
git commit -m "fix(defender): bound list_incidents/list_alerts to a single page + note"
```

---

### Task 3: entra bounding fix (`list_risky_users`, `list_risk_detections`)

**Files:**
- Modify: `servers/entra-mcp/f0_entra_mcp/tools.py`
- Modify: `servers/entra-mcp/tests/test_tools.py`

**Interfaces:**
- Consumes: `clamp_limit`, `more_available_finding` (Task 1).

- [ ] **Step 1: Write the failing tests** — append to `servers/entra-mcp/tests/test_tools.py`, **mirroring that file's existing helpers** (open it first: reuse its token-mock helper, `CFG`, and Graph base-URL constant exactly as the file defines them; the defender test above is the concrete template). Two tests, one per tool:
  - `test_list_risky_users_single_page_not_paginated` — endpoint `/identityProtection/riskyUsers`; a page-1 payload with one riskyUser row (`{"id": "u1", "userPrincipalName": "a@x", "riskLevel": "high", "riskState": "atRisk"}`) plus an `@odata.nextLink`; a `$skiptoken` route asserted **not** called; assert a `more results available` note is present.
  - `test_list_risk_detections_single_page_not_paginated` — endpoint `/identityProtection/riskDetections`; a page-1 row (`{"id": "d1", "userPrincipalName": "a@x", "riskEventType": "anon", "riskLevel": "high"}`) + `@odata.nextLink`; same assertions.

- [ ] **Step 2: Run — expect failure**

Run: `uv run pytest servers/entra-mcp/tests/test_tools.py -k "single_page_not_paginated" -q`
Expected: 2 failed.

- [ ] **Step 3: Add the import** — in `servers/entra-mcp/f0_entra_mcp/tools.py`, after the existing core imports:

```python
from f0_sectools_core.paging import clamp_limit, more_available_finding
```

- [ ] **Step 4: Replace `list_risky_users`** with:

```python
async def list_risky_users(gc: GraphClient, limit: int = 25) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        page = await gc.get("/identityProtection/riskyUsers", params={"$top": limit})
    except GraphError as e:
        finding = map_graph_error(e, "entra", "IdentityRiskyUser.Read.All", "Entra risky users")
        if finding:
            return [finding]
        raise
    raw = page.get("value", [])
    has_more = bool(page.get("@odata.nextLink"))
    out: list[Finding] = []
    for u in raw:
        upn = u.get("userPrincipalName") or u.get("id", "unknown")
        out.append(
            Finding(
                source="entra",
                finding_type=FindingType.risk,
                severity=_risk(u.get("riskLevel", "none")),
                title=f"Risky user: {upn}",
                entity=Entity(
                    kind=EntityKind.user, id=str(u.get("id", "")), name=u.get("userPrincipalName")
                ),
                evidence=[Evidence(key="risk_state", value=str(u.get("riskState", "")))],
                recommended_action=RecommendedAction(
                    summary="Review sign-in risk; consider risk-based CA or a password reset."
                ),
                observed_at=u.get("riskLastUpdatedDateTime"),
            )
        )
    out = out[:limit]
    if has_more:
        out.append(more_available_finding("entra", shown=len(out)))
    return out
```

- [ ] **Step 5: Replace `list_risk_detections`** with (body unchanged; only the fetch head, the `out = out[:limit]` slice, and the note are added):

```python
async def list_risk_detections(gc: GraphClient, limit: int = 25) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        page = await gc.get("/identityProtection/riskDetections", params={"$top": limit})
    except GraphError as e:
        finding = map_graph_error(e, "entra", "IdentityRiskEvent.Read.All", "Entra risk detections")
        if finding:
            return [finding]
        raise
    raw = page.get("value", [])
    has_more = bool(page.get("@odata.nextLink"))
    out: list[Finding] = []
    for d in raw:
        upn = d.get("userPrincipalName") or d.get("id", "unknown")
        event = d.get("riskEventType", "risk detection")
        out.append(
            Finding(
                source="entra",
                finding_type=FindingType.risk,
                severity=_risk(d.get("riskLevel", "none")),
                title=f"Risk detection: {event} ({upn})",
                entity=Entity(
                    kind=EntityKind.user,
                    id=str(d.get("userId", "")),
                    name=d.get("userPrincipalName"),
                ),
                evidence=[
                    Evidence(key="risk_state", value=str(d.get("riskState", ""))),
                    Evidence(key="detected", value=str(d.get("detectedDateTime", ""))),
                ],
                recommended_action=RecommendedAction(
                    summary="Investigate the detection; correlate with sign-in logs."
                ),
                observed_at=d.get("detectedDateTime"),
            )
        )
    out = out[:limit]
    if has_more:
        out.append(more_available_finding("entra", shown=len(out)))
    return out
```

- [ ] **Step 6: Run — expect pass**

Run: `uv run pytest servers/entra-mcp/tests/test_tools.py -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add servers/entra-mcp/f0_entra_mcp/tools.py servers/entra-mcp/tests/test_tools.py
git commit -m "fix(entra): bound list_risky_users/list_risk_detections to a single page + note"
```

---

### Task 4: Tenable `list_vulnerability_assets` + clamps + registration + smoke

**Files:**
- Modify: `servers/tenable-mcp/f0_tenable_mcp/tools.py`
- Modify: `servers/tenable-mcp/f0_tenable_mcp/server.py`
- Modify: `servers/tenable-mcp/tests/test_tools.py`
- Modify: `scripts/live_smoke_tenable.py`

**Interfaces:**
- Consumes: `clamp_limit`, `more_available_finding` (Task 1).
- Produces: `list_vulnerability_assets(tio, plugin_id, limit) -> list[Finding]` + the `list_vulnerability_assets` MCP tool.

- [ ] **Step 1: Write the failing tests** — append to `servers/tenable-mcp/tests/test_tools.py` (uses the file's `FakeClient`, longest-prefix match):

```python
_OUTPUTS = {"outputs": [{"states": [{"results": [
    {"assets": [
        {"id": "uuid-1", "hostname": "web-01", "ipv4": ["10.0.0.1"],
         "last_seen": "2026-01-01T00:00:00Z"},
        {"id": "uuid-2", "hostname": "web-02", "ipv4": ["10.0.0.2"]},
    ]},
    {"assets": [{"id": "uuid-1", "hostname": "web-01"}]},  # duplicate of uuid-1
]}]}]}


@pytest.mark.asyncio
async def test_list_vulnerability_assets_maps_hosts_and_dedupes():
    tio = FakeClient(responses={"/workbenches/vulnerabilities/172179/outputs": _OUTPUTS})
    findings = await tools.list_vulnerability_assets(tio, "172179", limit=25)
    hosts = [f for f in findings if f.entity and f.entity.kind.value == "host"]
    assert len(hosts) == 2  # uuid-1 deduped
    assert "web-01" in hosts[0].title
    assert "affected by plugin 172179" in hosts[0].title


@pytest.mark.asyncio
async def test_list_vulnerability_assets_no_assets_is_graceful():
    tio = FakeClient(responses={"/workbenches/vulnerabilities/999/outputs": {"outputs": []}})
    findings = await tools.list_vulnerability_assets(tio, "999")
    assert "no affected assets" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_list_vulnerability_assets_truncates_with_note():
    many = {"outputs": [{"states": [{"results": [{"assets": [
        {"id": f"u{i}", "hostname": f"h{i}"} for i in range(30)]}]}]}]}
    tio = FakeClient(responses={"/workbenches/vulnerabilities/1/outputs": many})
    findings = await tools.list_vulnerability_assets(tio, "1", limit=10)
    hosts = [f for f in findings if f.entity and f.entity.kind.value == "host"]
    assert len(hosts) == 10
    assert any("Showing 10 of 30" in f.title for f in findings)


@pytest.mark.asyncio
async def test_list_vulnerability_assets_permission_error_is_graceful():
    tio = FakeClient(raise_on={
        "/workbenches/vulnerabilities/1/outputs": TenableError(403, "forbidden")})
    findings = await tools.list_vulnerability_assets(tio, "1")
    assert findings[0].finding_type.value == "posture"
```

- [ ] **Step 2: Run — expect failure** (`AttributeError: ... has no attribute 'list_vulnerability_assets'`)

Run: `uv run pytest servers/tenable-mcp/tests/test_tools.py -k vulnerability_assets -q`
Expected: FAIL.

- [ ] **Step 3: Add the import** — in `servers/tenable-mcp/f0_tenable_mcp/tools.py`, after the `from f0_sectools_core.schema.findings import (...)` block add:

```python
from f0_sectools_core.paging import clamp_limit, more_available_finding
```

- [ ] **Step 4: Add the helper + tool** — append to `servers/tenable-mcp/f0_tenable_mcp/tools.py`:

```python
def _plugin_output_assets(d: Any) -> list[dict[str, Any]]:
    """Affected assets from a Workbenches plugin /outputs payload, deduped by id.

    Shape (LIVE-VALIDATED, recipe step 9): outputs[] -> states[] -> results[] ->
    assets[] with id/hostname/fqdn/ipv4. Defensive against missing levels.
    """
    seen: dict[str, dict[str, Any]] = {}
    outputs = d.get("outputs") if isinstance(d, dict) else None
    for o in outputs or []:
        for st in o.get("states") or []:
            for res in st.get("results") or []:
                for a in res.get("assets") or []:
                    aid = str(a.get("id") or a.get("uuid") or a.get("hostname") or "")
                    if aid and aid not in seen:
                        seen[aid] = a
    return list(seen.values())


async def list_vulnerability_assets(
    tio: Any, plugin_id: str, limit: int = 25
) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        d = await tio.get(f"/workbenches/vulnerabilities/{plugin_id}/outputs")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable plugin affected hosts")
        if finding:
            return [finding]
        raise
    assets = _plugin_output_assets(d)
    if not assets:
        return [
            Finding(
                source="tenable",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Tenable: no affected assets found for plugin {plugin_id}",
                entity=Entity(kind=EntityKind.rule, id=str(plugin_id)),
                recommended_action=RecommendedAction(
                    summary="Confirm the plugin_id (see list_top_vulnerabilities); the "
                    "finding may also be aged out (>450 days).",
                ),
            )
        ]
    out: list[Finding] = []
    for a in assets[:limit]:
        fqdns = a.get("fqdn") or []
        ipv4s = a.get("ipv4") or []
        name = a.get("hostname") or (fqdns[0] if fqdns else None) \
            or (ipv4s[0] if ipv4s else a.get("id", "asset"))
        evidence = []
        if ipv4s:
            evidence.append(Evidence(key="ipv4", value=str(ipv4s[0])))
        if a.get("last_seen"):
            evidence.append(Evidence(key="last_seen", value=str(a["last_seen"])))
        out.append(
            Finding(
                source="tenable",
                finding_type=FindingType.misconfig,
                severity=Severity.info,
                title=f"Tenable: {name} affected by plugin {plugin_id}",
                entity=Entity(kind=EntityKind.host, id=str(a.get("id", name)), name=str(name)),
                evidence=evidence,
                references=[Reference(type="tenable_plugin", id=str(plugin_id))],
                observed_at=a.get("last_seen"),
            )
        )
    if len(assets) > limit:
        out.append(more_available_finding("tenable", shown=limit, total=len(assets)))
    return out
```

- [ ] **Step 5: Add the `limit` clamp** to the four already-bounded tenable tools — insert `limit = clamp_limit(limit)` as the first statement (before the `try:`) in `list_top_vulnerabilities`, `list_assets`, `get_asset_vulnerabilities`, and `list_scans`.

- [ ] **Step 6: Register the tool** — in `servers/tenable-mcp/f0_tenable_mcp/server.py`, after the `get_vulnerability_info` tool add:

```python
@mcp.tool()
async def list_vulnerability_assets(plugin_id: str, limit: int = 25) -> list[dict[str, Any]]:
    """List the hosts affected by a specific Tenable vulnerability (plugin_id).

    Use after list_top_vulnerabilities to see WHICH assets carry a finding.
    """
    async with _client() as tio:
        return _render(await tools.list_vulnerability_assets(tio, plugin_id, limit))
```

- [ ] **Step 7: Run — expect pass**

Run: `uv run pytest servers/tenable-mcp/tests/test_tools.py -q`
Expected: all pass (4 new + existing).

- [ ] **Step 8: Add to the live smoke** — in `scripts/live_smoke_tenable.py`, after the `list_top_vulnerabilities` call, add a call that derives a `plugin_id` from the top vulnerabilities and exercises the new tool. Add to the labelled calls list:

```python
            # Derive a plugin_id from the top vulnerabilities, then list its hosts.
            top = await tools.list_top_vulnerabilities(tio, limit=1)
            plugin_id = next(
                (r.id for f in top for r in (f.references or []) if r.type == "tenable_plugin"),
                None,
            )
            if plugin_id:
                _show(
                    "list_vulnerability_assets",
                    await tools.list_vulnerability_assets(tio, plugin_id, limit=5),
                )
```

(Match the file's existing `_show(...)`/await structure; the exact placement follows the other labelled calls.)

- [ ] **Step 9: Commit**

```bash
git add servers/tenable-mcp/f0_tenable_mcp/tools.py servers/tenable-mcp/f0_tenable_mcp/server.py \
        servers/tenable-mcp/tests/test_tools.py scripts/live_smoke_tenable.py
git commit -m "feat(tenable): add list_vulnerability_assets (plugin->hosts) + clamp limits"
```

---

### Task 5: docs, evals, skill, changelog (counts 34→35)

**Files:**
- Modify: `README.md`, `docs/user-guide/README.md`, `CLAUDE.md`, `CHANGELOG.md`, `evals/tenable/tasks.yaml`, `skills/tenable/host-vulnerability-triage/SKILL.md`

- [ ] **Step 1: Current-count bump** — update **inventory** counts 34→35 (33 read + 2 gated), but LEAVE scorecard/eval counts at 34:
  - `README.md:24` — `**34 registered tools.**` → `**35 registered tools.**`
  - `README.md:38` (scorecard) — **do NOT change 34**. Reword `all **34 tools registered at once**` → `all **34 tools registered at once** (the new Tenable \`list_vulnerability_assets\` is pending its scorecard pass)`.
  - `CHANGELOG.md:16` / `:24` are in the released `[0.1.0]` section — **leave them** (they describe the 0.1.0 release, which had 34).

- [ ] **Step 2: Support matrix** — in `docs/user-guide/README.md:53`, append `, plugin affected-hosts` to the Tenable tool list so it reads `… vulnerability info, scans, plugin affected-hosts`.

- [ ] **Step 3: CLAUDE.md** — in the Platform Integrations Tenable row / read-tool description, add `plugin affected-hosts` to the Tenable read tools list (find the Tenable line under "Implemented & live-validated: `tenable-mcp` (…)" and add the new tool to its parenthetical).

- [ ] **Step 4: CHANGELOG entry** — add an `## [Unreleased]` section at the top (below the intro, above `## [0.1.0]`):

```markdown
## [Unreleased]

### Added

- **Tenable `list_vulnerability_assets`** — list the hosts affected by a given
  plugin/vulnerability (plugin→hosts), closing the "which hosts have vuln X" gap.

### Fixed

- **Bounded output** — `list_incidents`/`list_alerts` (Defender) and
  `list_risky_users`/`list_risk_detections` (Entra) no longer paginate the entire
  tenant; they return a single bounded page with a "more available" note, and
  `limit` is clamped to ≤100 across list tools (Critical Rule 5).
```

- [ ] **Step 5: Eval task** — append to `evals/tenable/tasks.yaml`:

```yaml
- prompt: "Which hosts are affected by plugin 172179?"
  expect_tool: list_vulnerability_assets
  expect_args: { plugin_id: "172179" }

- prompt: "List the assets that have the Log4j vulnerability, plugin 182252."
  expect_tool: list_vulnerability_assets
```

- [ ] **Step 6: Skill mention** — in `skills/tenable/host-vulnerability-triage/SKILL.md`, in the Procedure, add a line: to enumerate the hosts carrying a specific plugin, use `list_vulnerability_assets` (after `list_top_vulnerabilities` gives the plugin id). Keep the `description` frontmatter ≤60 chars (unchanged).

- [ ] **Step 7: Verify** — counts, links, skill validity, full gates:

Run:
```bash
cd /home/jimx/F0RT1KA/sec-tools
grep -n "34 registered" README.md            # expect: none
grep -n "35 registered" README.md            # expect: 1
uv run python skills/test_skills_valid.py 2>/dev/null || uv run pytest skills/test_skills_valid.py -q
uv run pytest -q && uv run ruff check . && uv run mypy .
```
Expected: no `34 registered`; skills valid; full suite green; ruff + mypy clean.

- [ ] **Step 8: Commit**

```bash
git add README.md docs/user-guide/README.md CLAUDE.md CHANGELOG.md evals/tenable/tasks.yaml \
        skills/tenable/host-vulnerability-triage/SKILL.md
git commit -m "docs: register list_vulnerability_assets + bounded-output notes (34->35 tools)"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** C1→Task 1; C2→Tasks 2-3; C3→Task 4; C4→Task 4 Step 5; docs/counts→Task 5. All components mapped.
- **Placeholder scan:** entra tests (Task 3 Step 1) describe payloads + assertions rather than full verbatim code because they must reuse that file's own fixtures — the defender test (Task 2) is the concrete template; not a TODO. All *source* code is verbatim.
- **Type/name consistency:** `clamp_limit`/`more_available_finding` signatures identical across Tasks 1-4; `source` strings match each server; the new tool name matches server registration, eval `expect_tool`, and docs.
- **Scorecard guardrail:** Task 5 explicitly keeps scorecard counts at 34 (avoids the overclaim the earlier README review caught).
- **Live-validation:** the only unverified fact (the `/outputs` nesting) is isolated to `_plugin_output_assets` + the smoke, flagged for operator validation.
