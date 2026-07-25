# Per-Persona Report Gathering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the three operational persona reports gather their own data (alerts with MITRE, incidents, detections, D&R rules, weak techniques, identity/compliance/exposure posture) instead of the CISO six-pillar rollup, and stop the source-based bucketing that silently drops findings.

**Architecture:** `scripts/report_gather.py`'s flat `_PILLAR_FACTORIES` becomes `GATHER_MAP: dict[persona, dict[group_label, factory]]`; `gather(persona, …)` runs that persona's factories concurrently, with graceful-partial and redaction unchanged. Because the gather is now persona-scoped, `sections.SECTION_MAPS`'s operational entries switch to `FindingGroup.all` and the dead source-based buckets are deleted from `group_findings`.

**Tech Stack:** Python 3.11+, existing MCP server tool functions (defender, limacharlie, projectachilles, entra, intune, tenable), pytest.

## Global Constraints

Copied from `docs/superpowers/specs/2026-07-25-report-persona-gathering-design.md` and CLAUDE.md. Every task's requirements implicitly include this section.

- **All platform wiring stays in `scripts/`.** `core/f0_sectools_core/reports/` must gain **no** new imports and stays PLATFORM-FREE + MODEL-FREE.
- **Graceful partial** — a factory that raises degrades to a `_degraded(...)` posture finding whose title contains `not configured` (so `is_not_assessed` classifies it); the report still generates and names the dark group under "not assessed". Never abort the run.
- **Redaction unchanged** — every gathered finding still passes through `redact_finding` before it leaves the gather.
- **Bounded output** — every list-returning tool call carries an explicit small limit (10–15).
- **CISO map is verbatim today's six pillars** — the CISO report (and its frozen golden) must be unchanged by this work.
- **`hunt` and `query_telemetry` are excluded** — they require an arbitrary category/indicator; a report must not fabricate a hypothesis.
- **NO real tenant identifiers** in tests/fixtures (use `Contoso`, `web-01.corp.local`, `CORP\jsmith`).
- **`scripts/` is mypy-EXEMPT** (do not run mypy on it); `core/` + servers stay mypy-strict clean. `ruff check .` must be clean.
- **Live-platform calls are USER-GATED** — only offline, monkeypatched tests run here.
- **Commit style:** conventional commits; stage specific files (never `git add -A`); each message ends with:
  ```
  Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
  ```
  Use `git commit -F` when the body contains backticks. **Do not push.**

## Reference: current code being changed

`scripts/report_gather.py` today holds:
- `_degraded(pillar: str, detail: str) -> Finding` — builds the "not configured" posture finding.
- Six `async def _pillar_*(window_hours: int) -> list[Finding]` factories (config hardening, vuln exposure, device compliance, data risk, attack validation, endpoint coverage) — each `load_dotenv`s its `.env.<platform>`, builds its client, and calls one tool.
- `_PILLAR_FACTORIES: dict[str, Callable[[int], Awaitable[list[Finding]]]]` — the flat six-pillar map.
- `_metric_from(pillar, findings) -> MetricCard` — headline → tile value, title → detail.
- `async def _run_pillar(pillar, factory, window_hours) -> tuple[str, list[Finding]]` — try/except → `_degraded`, then `redact_finding` each.
- `async def gather(persona, window_hours) -> tuple[list[Finding], ScopeMeta]` — ignores `persona`, iterates `_PILLAR_FACTORIES`, builds assessed/not_assessed/metrics/ScopeMeta.

Client-construction patterns already proven in this file (copy them):
- Graph platforms: `PlatformConfig.from_env("DEFENDER"|"INTUNE"|"PURVIEW"|"ENTRA")` + `async with GraphClient(cfg) as gc`
- Tenable: `async with TenableClient(TenableConfig.from_env()) as tio`
- ProjectAchilles: `async with ProjectAchillesClient(ProjectAchillesConfig.from_env()) as pa`
- LimaCharlie (sync SDK): `lc = LimaCharlieClient(LimaCharlieConfig.from_env())` then `await asyncio.to_thread(tools.<fn>, lc, ...)`

Tool signatures this plan wires (verified):
- defender: `list_alerts(gc, severity_min="high", limit=25)`, `list_incidents(gc, severity_min="medium", limit=25)`, `get_secure_score(gc)`
- limacharlie (sync): `list_dr_rules(lc, namespace="general", limit=50)`, `list_detections(lc, hours_back=24, limit=50, category=None)`, `get_org_overview(lc)`
- projectachilles: `get_weak_techniques(pa, days=30, limit=10)`
- entra: `list_conditional_access_policies(gc)`, `list_privileged_role_assignments(gc, limit=25)`, `list_risky_users(gc, limit=25)`
- intune: `get_compliance_summary(gc)`, `list_stale_devices(gc, days=30, limit=25)`
- tenable: `get_vulnerability_summary(tio)`, `list_top_vulnerabilities(tio, severity_min="high", limit=10)`

---

### Task 1: `GATHER_MAP` — per-persona gathering

**Files:**
- Modify: `scripts/report_gather.py`
- Test: `scripts/tests/test_gen_report.py`

**Interfaces:**
- Produces: `GATHER_MAP: dict[str, dict[str, Callable[[int], Awaitable[list[Finding]]]]]` keyed by normalized persona (`ciso`, `detection_engineer`, `threat_hunter`, `security_engineer`); `gather(persona, window_hours)` unchanged in signature, now persona-scoped and raising `ValueError` on an unknown persona.
- Renames: `_run_pillar` → `_run_group`; `_degraded(pillar, detail)` → `_degraded(group, detail)` (parameter rename only — the title format string stays `f"{group} not configured — pillar not assessed"` **changed to** `f"{group} not configured — not assessed"`; see Step 3).

- [ ] **Step 1: Write the failing tests**

Append to `scripts/tests/test_gen_report.py`:

```python
def test_gather_map_has_all_four_personas():
    assert set(report_gather.GATHER_MAP) == {
        "ciso", "detection_engineer", "threat_hunter", "security_engineer",
    }


def test_ciso_map_is_the_six_pillars():
    assert list(report_gather.GATHER_MAP["ciso"]) == [
        "Config hardening", "Attack validation", "Vulnerability exposure",
        "Device compliance", "Data risk", "Endpoint coverage",
    ]


def test_detection_engineer_gathers_its_own_groups():
    groups = set(report_gather.GATHER_MAP["detection_engineer"])
    assert groups == {
        "Alerts (MITRE)", "Incidents", "Detection rules",
        "Endpoint detections", "Weak techniques",
    }
    # it must NOT be the CISO pillar set
    assert "Data risk" not in groups


def test_security_engineer_gathers_identity_and_exposure():
    groups = set(report_gather.GATHER_MAP["security_engineer"])
    assert {"Conditional access", "Privileged roles", "Risky users",
            "Vulnerability exposure", "Device compliance"} <= groups


def test_threat_hunter_gathers_incidents_and_detections():
    groups = set(report_gather.GATHER_MAP["threat_hunter"])
    assert {"Incidents", "Alerts (MITRE)", "Endpoint detections",
            "Endpoint coverage"} <= groups


def test_gather_runs_only_the_personas_groups(monkeypatch):
    async def ok(window_hours):
        return [Finding(source="defender", finding_type=FindingType.alert,
                        severity=Severity.high, title="Suspicious PowerShell")]

    monkeypatch.setitem(report_gather.GATHER_MAP, "detection_engineer",
                        {"Alerts (MITRE)": ok, "Weak techniques": ok})
    findings, meta = asyncio.run(report_gather.gather("detection-engineer", 168))
    assert set(meta.assessed) == {"Alerts (MITRE)", "Weak techniques"}
    assert len(findings) == 2


def test_gather_rejects_unknown_persona():
    import pytest
    with pytest.raises(ValueError, match="Unknown persona"):
        asyncio.run(report_gather.gather("nonsense", 168))


def test_operational_persona_gets_no_metric_tiles(monkeypatch):
    # Operational groups return lists, not one headline number — a tile would be
    # meaningless, so pillar_metrics stays empty for them (CISO-only).
    async def ok(window_hours):
        return [Finding(source="defender", finding_type=FindingType.alert,
                        severity=Severity.high, title="Suspicious PowerShell")]

    monkeypatch.setitem(report_gather.GATHER_MAP, "threat_hunter", {"Incidents": ok})
    _findings, meta = asyncio.run(report_gather.gather("threat-hunter", 168))
    assert meta.pillar_metrics == []


def test_ciso_still_gets_metric_tiles(monkeypatch):
    from f0_sectools_core.schema.findings import Evidence

    async def ok(window_hours):
        return [Finding(source="defender", finding_type=FindingType.posture,
                        severity=Severity.low, title="Microsoft Secure Score: 90%",
                        evidence=[Evidence(key="headline", value="90%")])]

    monkeypatch.setitem(report_gather.GATHER_MAP, "ciso", {"Config hardening": ok})
    _findings, meta = asyncio.run(report_gather.gather("ciso", 168))
    assert [m.value for m in meta.pillar_metrics] == ["90%"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest scripts/tests/test_gen_report.py -q`
Expected: FAIL — `AttributeError: module 'report_gather' has no attribute 'GATHER_MAP'`.

- [ ] **Step 3: Rename the degradation helper's parameter and fix its title**

Replace `_degraded` (the word "pillar" no longer fits a group like "Alerts (MITRE)"):

```python
def _degraded(group: str, detail: str) -> Finding:
    return Finding(
        source=group.lower().replace(" ", "_"),
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"{group} not configured — not assessed",
        evidence=[Evidence(key="reason", value=redact_text(detail)[:300])],
    )
```

The title still contains `not configured`, which is in
`core/f0_sectools_core/reports/sections.py::DEGRADATION_MARKERS`, so
`is_not_assessed` still classifies it. Do not change that marker.

- [ ] **Step 4: Add the operational factories**

Add these below the existing six `_pillar_*` factories. Each mirrors the client
construction already used in this file.

```python
# ── Detection-engineer / threat-hunter factories ─────────────────────
async def _defender_alerts(window_hours: int) -> list[Finding]:
    from f0_defender_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.defender")
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return await tools.list_alerts(gc, severity_min="medium", limit=15)


async def _defender_incidents(window_hours: int) -> list[Finding]:
    from f0_defender_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.defender")
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return await tools.list_incidents(gc, severity_min="medium", limit=10)


async def _lc_dr_rules(window_hours: int) -> list[Finding]:
    from f0_limacharlie_mcp import tools
    from f0_limacharlie_mcp.client import LimaCharlieClient
    from f0_sectools_core.auth.config import LimaCharlieConfig
    load_dotenv(".env.limacharlie")
    lc = LimaCharlieClient(LimaCharlieConfig.from_env())
    return await asyncio.to_thread(tools.list_dr_rules, lc, "general", 15)


async def _lc_detections(window_hours: int) -> list[Finding]:
    from f0_limacharlie_mcp import tools
    from f0_limacharlie_mcp.client import LimaCharlieClient
    from f0_sectools_core.auth.config import LimaCharlieConfig
    load_dotenv(".env.limacharlie")
    lc = LimaCharlieClient(LimaCharlieConfig.from_env())
    return await asyncio.to_thread(tools.list_detections, lc, float(window_hours), 15)


async def _pa_weak_techniques(window_hours: int) -> list[Finding]:
    from f0_projectachilles_mcp import tools
    from f0_projectachilles_mcp.client import ProjectAchillesClient
    from f0_sectools_core.auth.config import ProjectAchillesConfig
    load_dotenv(".env.projectachilles")
    async with ProjectAchillesClient(ProjectAchillesConfig.from_env()) as pa:
        return await tools.get_weak_techniques(pa, limit=10)


# ── Security-engineer factories ──────────────────────────────────────
async def _entra_conditional_access(window_hours: int) -> list[Finding]:
    from f0_entra_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.entra")
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        return await tools.list_conditional_access_policies(gc)


async def _entra_privileged_roles(window_hours: int) -> list[Finding]:
    from f0_entra_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.entra")
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        return await tools.list_privileged_role_assignments(gc, limit=10)


async def _entra_risky_users(window_hours: int) -> list[Finding]:
    from f0_entra_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.entra")
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        return await tools.list_risky_users(gc, limit=10)


async def _intune_stale_devices(window_hours: int) -> list[Finding]:
    from f0_intune_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.intune")
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return await tools.list_stale_devices(gc, limit=10)


async def _tenable_top_vulns(window_hours: int) -> list[Finding]:
    from f0_sectools_core.auth.config import TenableConfig
    from f0_tenable_mcp import tools
    from f0_tenable_mcp.client import TenableClient
    load_dotenv(".env.tenable")
    async with TenableClient(TenableConfig.from_env()) as tio:
        return await tools.list_top_vulnerabilities(tio, limit=10)
```

- [ ] **Step 5: Replace `_PILLAR_FACTORIES` with `GATHER_MAP`**

Delete the `_PILLAR_FACTORIES` dict and put this in its place:

```python
# persona -> {group label: factory}. Patched in tests.
# The CISO map is the six-pillar rollup; operational personas gather their own
# working data (see docs/superpowers/specs/2026-07-25-report-persona-gathering-design.md).
GATHER_MAP: dict[str, dict[str, Callable[[int], Awaitable[list[Finding]]]]] = {
    "ciso": {
        "Config hardening": _pillar_config_hardening,
        "Attack validation": _pillar_attack_validation,
        "Vulnerability exposure": _pillar_vuln_exposure,
        "Device compliance": _pillar_device_compliance,
        "Data risk": _pillar_data_risk,
        "Endpoint coverage": _pillar_endpoint_coverage,
    },
    "detection_engineer": {
        "Alerts (MITRE)": _defender_alerts,
        "Incidents": _defender_incidents,
        "Detection rules": _lc_dr_rules,
        "Endpoint detections": _lc_detections,
        "Weak techniques": _pa_weak_techniques,
    },
    "threat_hunter": {
        "Incidents": _defender_incidents,
        "Alerts (MITRE)": _defender_alerts,
        "Endpoint detections": _lc_detections,
        "Endpoint coverage": _pillar_endpoint_coverage,
    },
    "security_engineer": {
        "Config hardening": _pillar_config_hardening,
        "Conditional access": _entra_conditional_access,
        "Privileged roles": _entra_privileged_roles,
        "Risky users": _entra_risky_users,
        "Device compliance": _pillar_device_compliance,
        "Stale devices": _intune_stale_devices,
        "Vulnerability exposure": _pillar_vuln_exposure,
        "Top vulnerabilities": _tenable_top_vulns,
    },
}
```

- [ ] **Step 6: Make `gather` persona-scoped (and metrics CISO-only)**

Rename `_run_pillar` → `_run_group` (rename its first parameter to `group` too;
body unchanged), then replace `gather`:

```python
async def _run_group(group: str, factory, window_hours: int) -> tuple[str, list[Finding]]:
    try:
        findings = await factory(window_hours)
    except Exception as exc:  # noqa: BLE001 — any platform failure degrades, never aborts
        return group, [_degraded(group, str(exc))]
    # The report is a shared artifact — apply the same structural redaction every
    # server's _render does (plus evidence-key-aware blanking), not just the
    # value-pattern net the emitters use. See core.redaction.redact.redact_finding.
    return group, [redact_finding(f) for f in findings]


async def gather(persona: str, window_hours: int) -> tuple[list[Finding], ScopeMeta]:
    key = persona.replace("-", "_")
    groups = GATHER_MAP.get(key)
    if groups is None:
        raise ValueError(f"Unknown persona '{persona}'. Valid: {', '.join(sorted(GATHER_MAP))}")
    results = await asyncio.gather(*[
        _run_group(group, factory, window_hours) for group, factory in groups.items()
    ])
    findings: list[Finding] = []
    assessed: list[str] = []
    not_assessed: list[str] = []
    metrics: list[MetricCard] = []
    for group, group_findings in results:
        findings.extend(group_findings)
        healthy = [f for f in group_findings if not is_not_assessed(f)]
        if healthy:
            assessed.append(group)
        else:
            not_assessed.append(group)
        # Tiles are an executive-tier device: a CISO group is one headline
        # posture finding, an operational group is a list of alerts/detections.
        if key == "ciso":
            metrics.append(_metric_from(group, group_findings))
    meta = ScopeMeta(
        generated_at="",  # stamped by the CLI
        tenant_label="",
        window_label=(
            f"Trailing {window_hours // 24} days"
            if window_hours >= 24
            else f"Trailing {window_hours}h"
        ),
        platforms_queried=[g.lower().replace(" ", "_") for g in groups],
        findings_count=len(findings),
        assessed=assessed,
        not_assessed=not_assessed,
        pillar_metrics=metrics,
    )
    return findings, meta
```

- [ ] **Step 7: Update the module docstring**

Replace the first paragraph so it describes groups, not pillars:

```python
"""Platform-aware finding gather for reports. Lives in scripts/ (may import
servers/*); core/reports stays platform-free. Each persona gathers its own
groups (GATHER_MAP) — the CISO the six-pillar rollup, the operational personas
their working data. Each factory mirrors the matching live_smoke_*.py client
construction. A platform that raises degrades to a posture finding so the report
still generates (graceful-partial)."""
```

- [ ] **Step 8: Run the tests**

Run: `uv run pytest scripts/tests/test_gen_report.py -v`
Expected: PASS (the new tests plus the pre-existing ones). If a pre-existing test
patched `_PILLAR_FACTORIES`, update it to `monkeypatch.setitem(report_gather.GATHER_MAP, "ciso", {...})`
— keep what it asserts, only change how it patches.

- [ ] **Step 9: Verify import-safety, full suite, lint**

Run:
```bash
uv run python -c "import sys; sys.path.insert(0,'scripts'); import report_gather, gen_report; print('import ok')"
uv run pytest -q
uv run ruff check .
```
Expected: `import ok` (no `.env` read or client built at import time), full suite green, ruff clean. Do **not** run mypy on `scripts/`.

- [ ] **Step 10: Commit**

```bash
git add scripts/report_gather.py scripts/tests/test_gen_report.py
git commit -m "feat(reports): per-persona GATHER_MAP so operational reports gather their own data"
# (append the two trailers)
```

---

### Task 2: Operational sections render everything gathered

**Files:**
- Modify: `core/f0_sectools_core/reports/sections.py`
- Test: `core/tests/test_reports_sections.py`
- Modify: `docs/user-guide/workflows.md`

**Interfaces:**
- Consumes: nothing from Task 1 (independent).
- Produces: `FindingGroup` reduced to `posture`, `top_risks`, `all`; `group_findings(findings, persona) -> dict[FindingGroup, list[Finding]]` returning only those three buckets; operational `SECTION_MAPS` entries use `FindingGroup.all`.

- [ ] **Step 1: Write the failing test**

Replace `test_group_findings_buckets_exposure_for_security_engineer` in
`core/tests/test_reports_sections.py` with:

```python
def test_group_findings_keeps_every_real_source():
    # Regression: the old source-based buckets silently dropped any finding whose
    # source wasn't in the persona's bucket, so an operational report showed only
    # part of what was gathered.
    vuln = Finding(source="tenable", finding_type=FindingType.risk,
                   severity=Severity.critical, title="3 critical vulns")
    alert = Finding(source="defender", finding_type=FindingType.alert,
                    severity=Severity.high, title="Suspicious PowerShell")
    weak = Finding(source="projectachilles", finding_type=FindingType.risk,
                   severity=Severity.medium, title="Weak technique T1059")
    grouped = group_findings([vuln, alert, weak], "detection_engineer")
    assert grouped[FindingGroup.all] == [vuln, alert, weak]
    assert grouped[FindingGroup.top_risks] == [vuln, alert, weak]


def test_finding_group_has_only_the_consumed_buckets():
    assert {g.value for g in FindingGroup} == {"posture", "top_risks", "all"}


def test_operational_sections_render_all_gathered_findings():
    for persona in ("detection_engineer", "threat_hunter", "security_engineer"):
        table = [s for s in SECTION_MAPS[persona] if s.kind is BlockKind.finding_table]
        assert table, persona
        assert all(s.group is FindingGroup.all for s in table), persona
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest core/tests/test_reports_sections.py -q`
Expected: FAIL — `FindingGroup` still has `detections`/`telemetry`/etc. and the
operational maps still point at `FindingGroup.detections` / `telemetry`.

- [ ] **Step 3: Simplify `FindingGroup` and `group_findings`**

In `core/f0_sectools_core/reports/sections.py`, replace the enum:

```python
class FindingGroup(StrEnum):
    posture = "posture"
    top_risks = "top_risks"
    all = "all"
```

and replace `group_findings` with:

```python
def group_findings(findings: list[Finding], persona: str) -> dict[FindingGroup, list[Finding]]:
    """Bucket findings for a persona's data sections.

    The gather is already persona-scoped (scripts/report_gather.py's GATHER_MAP),
    so a section renders everything gathered — bucketing by source used to drop
    any finding whose source wasn't in the persona's bucket. Degradation findings
    are excluded from the data buckets; they surface in the coverage section.
    """
    real = [f for f in findings if not is_not_assessed(f)]
    return {
        FindingGroup.all: list(real),
        FindingGroup.top_risks: list(real),
        FindingGroup.posture: [f for f in findings if f.finding_type is FindingType.posture],
    }
```

- [ ] **Step 4: Point the operational sections at `FindingGroup.all`**

In `SECTION_MAPS`, change the `finding_table` entry for each of the three
operational personas so its group is `FindingGroup.all`:

```python
    "detection_engineer": [
        SectionSpec(BlockKind.narrative, "sec_executive_summary", _OPS),
        SectionSpec(BlockKind.finding_table, "sec_findings", _OPS, FindingGroup.all),
        SectionSpec(BlockKind.coverage, "sec_scope", _OPS),
        SectionSpec(BlockKind.open_questions, "sec_open_questions", _OPS),
        SectionSpec(BlockKind.provenance, "sec_provenance", _OPS),
    ],
    "threat_hunter": [
        SectionSpec(BlockKind.narrative, "sec_executive_summary", _OPS),
        SectionSpec(BlockKind.finding_table, "sec_findings", _OPS, FindingGroup.all),
        SectionSpec(BlockKind.coverage, "sec_scope", _OPS),
        SectionSpec(BlockKind.open_questions, "sec_open_questions", _OPS),
        SectionSpec(BlockKind.provenance, "sec_provenance", _OPS),
    ],
```
(`security_engineer` already uses `FindingGroup.all` — leave it.)

- [ ] **Step 5: Run the tests**

Run: `uv run pytest core/tests/test_reports_sections.py core/tests/test_reports_builder.py -v`
Expected: PASS. The CISO golden is unaffected (its sections use
`metric_grid` + `finding_rollup`/`top_risks`, untouched). If
`golden_detection_en.md` changes, that is expected **only** if its fixture has a
source the old `detections` bucket dropped — re-freeze it, READ it, and confirm
the added rows are real findings from the fixture. If it changes in any other
way, STOP and report.

- [ ] **Step 6: Fix the docs**

In `docs/user-guide/workflows.md`, in the report section:

1. Change the heading:
   `## Generate a posture report (any persona) — Markdown + PDF, EN/ES`
   →
   `## Generate a posture report (any persona) — Markdown, HTML + PDF, EN/ES`
2. Replace the sentence describing the personas' content with an accurate one:

```markdown
The **CISO** report is executive-restrained (a six-pillar posture at a glance
plus compact one-line top risks). The **operational** personas gather their own
working data and render it as dense finding rows with evidence and MITRE
technique references: the **detection engineer** gets Defender alerts and
incidents, LimaCharlie D&R rules and endpoint detections, and ProjectAchilles
weak techniques; the **threat hunter** gets incidents, MITRE-bearing alerts,
endpoint detections and sensor coverage; the **security engineer** gets Secure
Score, Entra conditional-access/privileged-role/risky-user posture, Intune
compliance and stale devices, and Tenable exposure.
```

- [ ] **Step 7: Verify everything**

Run:
```bash
uv run pytest -q
uv run mypy core/ servers/
uv run ruff check .
uv run pytest scripts/tests/test_gen_docs.py skills/test_skills_valid.py integrations/test_integrations_valid.py -q
```
Expected: all green (full suite, mypy strict on core+servers, ruff, drift guards).

- [ ] **Step 8: Commit**

```bash
git add core/f0_sectools_core/reports/sections.py core/tests/test_reports_sections.py docs/user-guide/workflows.md
# add core/tests/fixtures/reports/golden_detection_en.md only if Step 5 legitimately re-froze it
git commit -m "fix(reports): operational sections render every gathered finding; sync docs"
# (append the two trailers)
```

---

## Post-implementation (operator-gated, not a task)

Generate a live **detection-engineer** report and confirm it contains real alerts
and detections with MITRE references rather than Secure Score. Live calls need
explicit operator go-ahead.

## Self-review (author)

- **Spec coverage:** `GATHER_MAP` (T1 S5) ✅ · per-persona tool tables (T1 S4–S5) ✅ · Entra as 7th source (T1 S4) ✅ · `hunt`/`query_telemetry` excluded (not wired anywhere) ✅ · operational sections render all + `FindingGroup` simplification (T2 S3–S4) ✅ · CISO-only tiles (T1 S6) ✅ · graceful-partial + `not configured` marker preserved (T1 S3) ✅ · redaction preserved (T1 S6, `_run_group` body unchanged) ✅ · bounded limits (T1 S4) ✅ · docs fixes (T2 S6) ✅ · tests (T1 S1, T2 S1) ✅.
- **Placeholder scan:** none — every step carries the exact code or command.
- **Type consistency:** `GATHER_MAP` value type matches `_run_group(group, factory, window_hours)`; `_degraded(group, detail)` used only in `_run_group`; `group_findings` returns the three-member `FindingGroup`; `SECTION_MAPS` references only `FindingGroup.all`/`top_risks`/`posture`.

## Out of scope

Charts/gauges; interactive hunts in reports; per-persona narrative templates; new server tools; findings-schema or renderer changes.
