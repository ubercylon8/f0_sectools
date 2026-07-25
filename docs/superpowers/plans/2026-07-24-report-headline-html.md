# Report Headline Metrics + HTML Output — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the giant "Posture at a glance" tiles (they rendered the whole metric sentence at big-number size) by letting each pillar tool emit a compact **headline**, redesign the tiles (Direction A) + overhaul the stylesheet for a calm type scale, and make **HTML a first-class output**.

**Architecture:** Six CISO pillar tools add one `Evidence(key="headline", value="<compact>")`. The report layer prefers it: `report_gather._metric_from` uses it for the tile value (+ the finding title as a new `MetricCard.detail`), and `emit._grounding_clause` uses it for the executive one-liner; operational evidence rendering hides the `headline` key. `emit._metric_card` renders the Direction-A tile; `assets/report.css` gets one type scale for both the standalone `.html` (screen) and the WeasyPrint PDF (print); `gen_report.py` writes `<out>.html`.

**Tech Stack:** Python 3.11+, the existing `core/f0_sectools_core/reports/` engine + the six MCP servers, pytest.

## Global Constraints

Copied from CLAUDE.md and `docs/superpowers/specs/2026-07-24-report-headline-and-html-design.md`. Every task's requirements implicitly include this section.

- **`core/f0_sectools_core/reports/` stays PLATFORM-FREE + MODEL-FREE** (no `servers/*`/`httpx`/SDK). Report layer imports only from `content`, `theme`, `redaction.redact`, `schema.findings`, stdlib.
- **Redaction unchanged** — every emitted string still goes through `_r`/`_e`; the report gather still runs `redact_finding` (the `headline` key is not secret-hinting, so it survives).
- **NO real tenant identifiers** in tests/fixtures/goldens (Contoso, web-01.corp.local, CORP\jsmith, rare.example.test).
- **Goldens deterministic** — `generated_at` injected in tests.
- **The findings schema is UNCHANGED** — `headline` is an ordinary `Evidence` entry, not a schema field. The chat persona renderers (`core/.../renderers/`) are UNCHANGED.
- **mypy strict clean for `core/` + servers; ruff clean.** gen_docs reference is unaffected (adding an evidence entry inside a tool changes neither its signature nor docstring) — but run the drift guard to confirm.
- **Commit style:** conventional commits; stage specific files (never `git add -A`); each message ends with:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
  ```
  `git commit -F` when the body has backticks. **Do not push.**

---

### Task 1: Six pillar tools emit a `headline` evidence entry

**Files (each is a tool + its contract test):**
- `servers/defender-mcp/f0_defender_mcp/tools.py` (`get_secure_score`) + `servers/defender-mcp/tests/test_tools.py`
- `servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py` (`get_defense_score`) + its test
- `servers/tenable-mcp/f0_tenable_mcp/tools.py` (`get_vulnerability_summary`) + its test
- `servers/intune-mcp/f0_intune_mcp/tools.py` (`get_compliance_summary`) + its test
- `servers/purview-mcp/f0_purview_mcp/tools.py` (`get_dlp_summary`) + its test
- `servers/limacharlie-mcp/f0_limacharlie_mcp/tools.py` (`get_org_overview`) + its test

**Interfaces:** each of the six posture findings gains a first evidence entry `Evidence(key="headline", value="<compact>")`. No signature/docstring changes.

Add the headline **as the first evidence entry** in each tool (compact phrase, ≤ ~16 chars). The number is already computed for the title.

- [ ] **Step 1: Add the headline to each tool**

Defender `get_secure_score` — `pct` is already computed; prepend to the `evidence=[...]` list:
```python
evidence=[
    Evidence(key="headline", value=f"{pct:.0f}%"),
    Evidence(key="current_score", value=f"{current:.1f}"),
    Evidence(key="max_score", value=f"{maximum:.1f}"),
],
```

ProjectAchilles `get_defense_score` — `score` is computed; insert at the front of `evidence`:
```python
evidence = [
    Evidence(key="headline", value=f"{score:.0f}% blocked"),
    Evidence(key="tests_protected", value=str(d.get("protectedCount", 0))),
    ...  # rest unchanged
]
```

Tenable `get_vulnerability_summary` — prepend to the built `evidence` list:
```python
evidence = [Evidence(key="headline", value=f"{counts[Severity.critical]} critical")] + [
    Evidence(key=s.value, value=str(counts[s]))
    for s in (Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info)
]
```

Intune `get_compliance_summary` — prepend (guard divide-by-zero):
```python
pct = round(compliant / total * 100) if total else 0
evidence=[
    Evidence(key="headline", value=f"{pct}% compliant"),
    Evidence(key="devices_total", value=str(total)),
    ...  # rest unchanged
],
```

Purview `get_dlp_summary` — prepend:
```python
evidence=[
    Evidence(key="headline", value=f"{len(alerts)} DLP alerts"),
    Evidence(key="alerts_total", value=str(len(alerts))),
    Evidence(key="by_severity", value=fmt(by_sev)),
    Evidence(key="by_status", value=fmt(by_status)),
],
```

LimaCharlie `get_org_overview` — insert the headline at the front of the `evidence` list (before `sensors_total`), where `online` is already computed:
```python
evidence = [
    Evidence(key="headline", value=f"{online} online"),
    Evidence(key="sensors_total", value=str(len(sensors))),
    Evidence(key="sensors_online", value=str(online)),
    Evidence(key="dr_rules", value=str(n_rules)),
    Evidence(key="detections_24h", value=str(len(detections))),
]
# (the existing sleepers .insert(2, …) still runs after; it inserts among the raw keys)
```
Note: LimaCharlie inserts `sensors_dormant_sleepers` at index 2 when present. With `headline` now at index 0, index 2 is still among the raw sensor keys — acceptable (the headline stays first). If the reviewer prefers, bump the insert index to 3; either is fine as long as `headline` is index 0.

- [ ] **Step 2: Update each contract test to assert the headline**

For each server's test that exercises the pillar tool, add an assertion that the returned posture finding has an evidence entry `key == "headline"` with the expected value for that test's mocked data (e.g. Defender mock with currentScore/maxScore → `"<pct>%"`; Tenable mock with N critical → `"N critical"`; etc.). Find the existing test by grepping the test file for the tool name; assert on `findings[0].evidence`. Keep it a focused addition to the existing test.

- [ ] **Step 3: Run the six servers' tests**

Run: `uv run pytest servers/defender-mcp servers/projectachilles-mcp servers/tenable-mcp servers/intune-mcp servers/purview-mcp servers/limacharlie-mcp -q`
Expected: all pass.

- [ ] **Step 4: Types, lint, drift guard**

Run: `uv run mypy core/ servers/ && uv run ruff check . && uv run pytest scripts/tests/test_gen_docs.py -q`
Expected: clean (gen_docs reference unchanged — no signature/docstring change).

- [ ] **Step 5: Commit**

```bash
git add servers/defender-mcp/f0_defender_mcp/tools.py servers/defender-mcp/tests/test_tools.py \
  servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py servers/projectachilles-mcp/tests/ \
  servers/tenable-mcp/f0_tenable_mcp/tools.py servers/tenable-mcp/tests/ \
  servers/intune-mcp/f0_intune_mcp/tools.py servers/intune-mcp/tests/ \
  servers/purview-mcp/f0_purview_mcp/tools.py servers/purview-mcp/tests/ \
  servers/limacharlie-mcp/f0_limacharlie_mcp/tools.py servers/limacharlie-mcp/tests/
git commit -m "feat(reports): pillar tools emit a compact 'headline' evidence for report tiles"
# (append the two trailers; stage only the tool + test files you actually changed)
```

---

### Task 2: Report layer consumes the headline (logic + Markdown/HTML tile content + goldens)

**Files:**
- Modify: `core/f0_sectools_core/reports/content.py` (`MetricCard.detail`)
- Modify: `core/f0_sectools_core/reports/emit.py` (headline helpers, grounding, operational evidence skip, tile content)
- Modify: `scripts/report_gather.py` (`_metric_from`)
- Modify: `core/tests/test_reports_emit.py`, `core/tests/test_reports_builder.py`, `scripts/tests/test_gen_report.py`
- Modify fixtures/goldens: `core/tests/fixtures/reports/findings_ciso.json`, `golden_ciso_en.md`, `golden_detection_en.md`

**Interfaces:**
- `MetricCard(label, value, state, detail: str = "")`
- emit: `_headline(f) -> str`, `_display_evidence(f) -> list[Evidence]`; `_grounding_clause` prefers headline.
- `report_gather._metric_from` returns a `MetricCard` with a compact `value` (headline) + `detail` (title).

- [ ] **Step 1: `MetricCard.detail`**

In `content.py`, add a defaulted field to the frozen `MetricCard` dataclass:
```python
@dataclass(frozen=True)
class MetricCard:
    label: str
    value: str
    state: str
    detail: str = ""
```

- [ ] **Step 2: emit — headline helpers, grounding, operational evidence skip**

In `emit.py` add:
```python
def _headline(f: Finding) -> str:
    return next((e.value for e in f.evidence if e.key == "headline"), "")


def _display_evidence(f: Finding) -> list[Evidence]:
    """Evidence to show in operational rows — the 'headline' key is a tile hint, not detail."""
    return [e for e in f.evidence if e.key != "headline"]
```
(Import `Evidence` from `f0_sectools_core.schema.findings` alongside `Finding`.)

Rewrite `_grounding_clause` to prefer the headline (skipping it when already in the title):
```python
def _grounding_clause(f: Finding) -> str:
    hl = _headline(f)
    if hl and hl not in f.title:
        return hl
    if f.entity is not None and f.entity.name:
        return f.entity.name
    for e in _display_evidence(f):
        return f"{e.key}: {e.value}"
    return ""
```

In `_md_findings` and `_html_findings`, change the operational-tier evidence loops from `f.evidence` to `_display_evidence(f)` so the `headline` key never renders as a sub-bullet.

- [ ] **Step 3: emit — Markdown metric line carries value/label/state/detail**

In `_md_body`, replace the `metric_grid` branch:
```python
    if s.kind is BlockKind.metric_grid:
        return [_md_metric(m) for m in s.metrics]
```
and add:
```python
def _md_metric(m: MetricCard) -> str:
    line = f"- **{_r(m.value)}** — {_r(m.label)} ({_r(m.state)})"
    if m.detail:
        line += f" · {_r(m.detail)}"
    return line
```

- [ ] **Step 4: emit — Direction-A HTML tile**

Replace `_metric_card`:
```python
def _metric_card(m: MetricCard) -> str:
    state = _e(m.state).replace(" ", "-")
    detail = f'<div class="metric__detail">{_e(m.detail)}</div>' if m.detail else ""
    return (
        '<div class="metric">'
        f'<div class="metric__label">{_e(m.label)}</div>'
        f'<div class="metric__value">{_e(m.value)}</div>'
        f'<div class="metric__state metric__state--{state}">{_e(m.state)}</div>'
        f'{detail}</div>'
    )
```

- [ ] **Step 5: report_gather `_metric_from` uses the headline + detail**

In `scripts/report_gather.py`, delete the `_PILLAR_METRIC_KEY` dict and rewrite `_metric_from`:
```python
def _metric_from(pillar: str, findings: list[Finding]) -> MetricCard:
    real = [f for f in findings if not is_not_assessed(f)]
    if not real:
        return MetricCard(pillar, "not assessed", "not-assessed")
    f = real[0]
    headline = next((e.value for e in f.evidence if e.key == "headline"), "")
    value = headline or f.title[:32]  # defensive fallback if a tool lacks a headline
    state = {"critical": "exposure", "high": "needs-work", "medium": "needs-work"}.get(
        f.severity.value, "strong")
    return MetricCard(pillar, value, state, detail=f.title)
```

- [ ] **Step 6: Update fixtures + tests, then re-freeze goldens**

- In `core/tests/fixtures/reports/findings_ciso.json`, add a `headline` evidence entry to the **tenable** finding (first in its evidence list), e.g. `{"key": "headline", "value": "3 critical"}`, so the top-risk grounding exercises the headline path.
- In `core/tests/test_reports_builder.py`, give the `MetricCard` in `_scope()` a `detail` (e.g. `MetricCard("Config hardening", "62%", "needs-work", detail="Microsoft Secure Score 1130/1816")`).
- Add/adjust tests:
  - emit: a metric-grid MD test asserting the line is `- **62%** — Config hardening (needs-work) · …`; an HTML test asserting `metric__value` holds the compact value and `metric__detail` is present.
  - emit: `_grounding_clause` prefers headline (a finding with `headline` not in title → clause == headline) and skips when in-title.
  - emit: operational rows do NOT render a `- headline: …` sub-bullet (`_display_evidence`).
  - `scripts/tests/test_gen_report.py`: a `_metric_from`/gather test — a healthy pillar finding carrying `headline` yields a `MetricCard` whose `value` is the headline and `detail` is the title (not the title as value).
- Re-freeze `golden_ciso_en.md` and `golden_detection_en.md` (run the freeze snippets from the prior plans / the builder-test fixtures), READ both, and confirm: CISO metric lines now lead with the compact value; the tenable top risk grounds on `3 critical`; detection golden's operational rows are unchanged except no `headline` sub-bullet (there is none in that fixture, so it should be byte-identical — if it changed unexpectedly, STOP and report). Commit the re-frozen goldens.

- [ ] **Step 7: Verify**

Run:
```bash
uv run pytest core/tests/test_reports_emit.py core/tests/test_reports_builder.py scripts/tests/test_gen_report.py -v
uv run pytest -q
uv run mypy core/ servers/
uv run ruff check .
```
Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add core/f0_sectools_core/reports/content.py core/f0_sectools_core/reports/emit.py \
  scripts/report_gather.py core/tests/test_reports_emit.py core/tests/test_reports_builder.py \
  scripts/tests/test_gen_report.py core/tests/fixtures/reports/
git commit -m "feat(reports): consume headline for compact metric tiles + grounded exec one-liners"
# (append trailers)
```

---

### Task 3: Stylesheet overhaul + `.report` wrapper + HTML output + docs

**Files:**
- Modify: `core/f0_sectools_core/reports/assets/report.css` (full overhaul)
- Modify: `core/f0_sectools_core/reports/emit.py` (`to_html` wraps content in `<div class="report">`)
- Modify: `scripts/gen_report.py` (write `<out>.html`)
- Modify: `core/tests/test_reports_emit.py` (HTML-structure assertions)
- Modify: `docs/user-guide/workflows.md` (note the `.html` output)

**Interfaces:** presentation only. `to_markdown` output (and the MD goldens) are UNAFFECTED — CSS/HTML changes do not touch Markdown.

- [ ] **Step 1: `to_html` wraps content in a document card**

In `emit.py` `to_html`, wrap the cover+sections in a `.report` div so the stylesheet can center it as a card on screen and full-bleed it in print. Change the body assembly to:
```python
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<style>{inline_css(content.tier)}</style></head>"
        f"<body class='{tier_class}'><div class=\"report\">{''.join(body)}</div></body></html>"
    )
```
(`body` still starts with the cover div and the sections, unchanged.)

- [ ] **Step 2: Overhaul `assets/report.css`**

Replace the file with one stylesheet serving screen (`.html`) and print (PDF) — a single calm type scale, Direction-A metric tiles, re-proportioned finding rows:

```css
/* f0_sectools report theme — one stylesheet for screen (.html) and print (PDF). */
:root {
  --navy:#0f1830; --gold:#d4a24e; --ink:#1a1f2b; --body:#26303f; --muted:#8a93a6; --rule:#eef0f4;
  --sev-critical:#a11; --sev-high:#a6641b; --sev-medium:#8a6d1b; --sev-low:#2f7d4f; --sev-info:#6e7781;
}
* { box-sizing:border-box; }
body {
  font-family:-apple-system,"Segoe UI",Roboto,sans-serif;
  color:var(--body); line-height:1.55; font-size:13.5px; margin:0; background:#eaedf3;
}
.report {
  max-width:760px; margin:24px auto; background:#fff; color:var(--ink);
  border-radius:8px; overflow:hidden; box-shadow:0 8px 30px rgba(0,0,0,.16);
}
.report__cover { background:var(--navy); color:#fff; padding:30px 34px; border-bottom:3px solid var(--gold); }
.report__kicker { font-size:10px; letter-spacing:2.5px; color:var(--gold); font-weight:700; }
.report__title { font-size:26px; font-weight:600; margin-top:11px; letter-spacing:-.2px; }
.report__subtitle { font-size:12.5px; color:#9fb0d0; margin-top:11px; line-height:1.5; }
.report__section { padding:22px 34px; border-top:1px solid var(--rule); }
.report__h { font-size:10.5px; font-weight:700; letter-spacing:.7px; text-transform:uppercase; color:var(--muted); margin:0 0 12px; }
.report__section p { margin:0; font-size:13.5px; color:var(--body); }
/* Metric tiles — Direction A (label · big number · state · detail) */
.metric-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:22px 26px; }
.metric__label { font-size:9px; letter-spacing:.8px; text-transform:uppercase; color:var(--muted); font-weight:700; }
.metric__value { font-size:34px; font-weight:700; color:var(--navy); line-height:1.05; margin:3px 0; }
.metric__state { font-size:11px; font-weight:600; }
.metric__detail { font-size:10px; color:var(--muted); margin-top:3px; }
.metric__state--strong { color:var(--sev-low); }
.metric__state--needs-work { color:var(--sev-high); }
.metric__state--exposure { color:var(--sev-critical); }
.metric__state--not-assessed { color:var(--muted); }
/* Finding rows — operational */
.finding { border-left:4px solid var(--sev-info); padding:7px 11px; margin-bottom:7px; background:#f6f8fa; border-radius:0 4px 4px 0; }
.finding--critical { border-left-color:var(--sev-critical); background:#faf0f0; }
.finding--high { border-left-color:var(--sev-high); background:#fdf7e6; }
.finding--medium { border-left-color:var(--sev-medium); background:#fdf9ee; }
.finding--low { border-left-color:var(--sev-low); }
.finding__title { font-size:13px; font-weight:700; }
.finding__meta { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:10px; color:#667; margin-top:2px; }
.finding__evidence { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:10px; color:#556; margin-top:1px; }
.oq { border-left:3px solid var(--gold); background:#fdf8ef; padding:9px 13px; margin:7px 0; border-radius:0 4px 4px 0; font-size:12.5px; }
.coverage { background:#f8f9fb; font-size:12px; color:#445; }
.provenance { font-size:9.5px; color:var(--muted); }
.report--operational .report__title { font-size:22px; }
@media print { body { background:#fff; } .report { max-width:none; margin:0; border-radius:0; box-shadow:none; } }
@page { size:A4; margin:16mm 15mm; }
```

- [ ] **Step 3: `gen_report.py` writes `<out>.html`**

In `_main`, after writing the Markdown and before the `--pdf` block, always write the HTML:
```python
    html_path = args.out.with_suffix(".html")
    html_path.write_text(out.html, encoding="utf-8")
    print(f"wrote {html_path}")
```

- [ ] **Step 4: HTML-structure tests**

Update/add emit HTML tests:
- `to_html` output contains `<div class="report">` (the card wrapper) and still starts with `<!doctype html>`.
- The inlined `<style>` contains `.metric` and `@page` and `@media print` (theme present); the metric tile renders `metric__label`/`metric__value`/`metric__state`/`metric__detail`.
- The existing self-contained/no-external-URL and severity-class assertions still hold. Adjust any assertion that assumed the old flat body (no `.report` wrapper) or the old `_metric_card` markup.

- [ ] **Step 5: Docs — note the `.html` output**

In `docs/user-guide/workflows.md`, in the "Generate a posture report" section, update the sentence about outputs to mention the standalone HTML, e.g.: "It writes `report.md` and a standalone, self-contained `report.html` (open in any browser); with `--pdf` it also writes `report.pdf` (WeasyPrint renders the same HTML)."

- [ ] **Step 6: Verify (incl. link/drift guards)**

Run:
```bash
uv run pytest core/tests/test_reports_emit.py -v
uv run pytest -q
uv run mypy core/ servers/
uv run ruff check .
uv run pytest scripts/tests/test_gen_docs.py skills/test_skills_valid.py integrations/test_integrations_valid.py -q
```
Expected: all green. (The Markdown goldens are unchanged by this task — CSS/HTML only.)

- [ ] **Step 7: Commit**

```bash
git add core/f0_sectools_core/reports/assets/report.css core/f0_sectools_core/reports/emit.py \
  scripts/gen_report.py core/tests/test_reports_emit.py docs/user-guide/workflows.md
git commit -m "feat(reports): Direction-A tile CSS overhaul + standalone .html output"
# (append trailers)
```

---

## Post-implementation (operator-gated, not a task)

Regenerate the live CISO report EN + ES (`gen_report.py … --pdf`) and eyeball the `.html` + `.pdf`: compact tiles, calm proportion. Live calls need explicit operator go-ahead.

## Self-review (author)

- Spec coverage: headline in 6 tools (T1) ✅; MetricCard.detail + grounding + operational skip + `_metric_from` (T2) ✅; Direction-A tiles + CSS + `.html` output + `.report` wrapper (T3) ✅; docs note (T3) ✅.
- Each task stays green: T1 (tools+tests), T2 re-freezes MD goldens (grounding + MD tile line change), T3 is presentation-only (no MD golden impact).
- No placeholders; exact code per step; types consistent (`MetricCard.detail`, `_headline`/`_display_evidence` signatures, `_metric_from` return).

## Out of scope

Charts/gauges; screen-only JS; re-deriving metric state; persona-specific gathering. (Per spec.)
