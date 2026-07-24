# Report Finding Rows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give report finding sections a report-owned, tier-aware row renderer used by both the Markdown and HTML emitters — operational reports carry evidence + MITRE, the CISO report stays one-line compact, and the MD/PDF outputs stop drifting (and the stray `## Security posture rollup` heading disappears).

**Architecture:** Replace `emit.py`'s use of the chat persona renderer (`render_findings`) for report findings with two report-owned functions, `_md_findings(findings, tier)` and `_html_findings(findings, tier)`, that branch on `Section.tier` (`"executive"` = compact one-liner, `"operational"` = dense with source + `ATT&CK:` + all evidence). Confined to `emit.py` + one small CSS class + tests + golden fixtures.

**Tech Stack:** Python 3.11+, the existing `core/f0_sectools_core/reports/` engine, pytest.

## Global Constraints

Copied verbatim from CLAUDE.md and the design spec (`docs/superpowers/specs/2026-07-24-report-finding-rows-design.md`). Every task's requirements implicitly include this section.

- **`core/f0_sectools_core/reports/` stays PLATFORM-FREE + MODEL-FREE** — no `servers/*`/`httpx`/SDK imports. `emit.py` may import from `content`, `theme`, `f0_sectools_core.redaction.redact`, `f0_sectools_core.schema.findings`, and stdlib (`html`) only.
- **Redaction unchanged and mandatory** — every emitted string still goes through `_r` (Markdown) / `_e` (HTML). The new row renderers redact every value (title, source, evidence key/value, grounding clause, MITRE ids).
- **NO real tenant identifiers** — fixtures/tests/goldens use neutral values only (Contoso, web-01.corp.local, CORP\jsmith).
- **Golden files are DETERMINISTIC** — `generated_at` is injected via `ScopeMeta` (fixed string in tests), never from the clock.
- **mypy strict clean for `core/` (+ servers); ruff clean.** The findings schema and the chat persona renderers (`core/f0_sectools_core/renderers/`) are UNCHANGED — they are used elsewhere.
- **Unbounded evidence** at the operational tier (operator's choice — a report is a human-facing document; findings are already bounded by the gather layer). No per-finding truncation.
- **Commit style:** conventional commits; stage specific files (never `git add -A`). Every commit message ends with:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
  ```
  Use `git commit -F <file>` when the message body contains backticks. **Do not push** — commit locally and wait for explicit instruction.

## Reference: current `emit.py` shape (what you are changing)

- `to_markdown` loops sections calling `_md_body(s, content)`; `to_html` calls `_html_body(s, content)`.
- The finding branch of `_md_body` currently does `render_findings(s.findings, _persona(content))`; the finding branch of `_html_body` currently does `_finding_row(f)` per finding (title + `source · severity`, no evidence/MITRE).
- `content` is used ONLY by `_persona(content)` in `_md_body`'s finding branch; `_html_body` never uses `content`. After this change neither needs it.
- Helpers present: `_r`, `_e`, `_sorted`, `_SEV_CLASS`, `_metric_card`. `Finding` has `severity` (StrEnum `.value`), `source`, `title`, `entity{kind,id,name}`, `evidence: list[Evidence{key,value}]`, `references: list[Reference{type,id,url}]` (MITRE refs have `type == "mitre"`, `id` = technique e.g. `T1190`).

---

### Task 1: Report-owned tier-aware finding rows in `emit.py`

**Files:**
- Modify: `core/f0_sectools_core/reports/emit.py`
- Modify: `core/f0_sectools_core/reports/assets/report.css` (add `.finding__evidence`)
- Modify: `core/tests/test_reports_emit.py` (row-format assertions for both tiers)
- Modify: `core/tests/fixtures/reports/golden_ciso_en.md` (re-freeze — CISO rows become compact one-liners, stray heading gone)

**Interfaces:**
- Produces (internal to `emit.py`): `_md_findings(findings: list[Finding], tier: str) -> list[str]`, `_html_findings(findings: list[Finding], tier: str) -> list[str]`, `_sev_tag(f) -> str`, `_mitre_ids(f) -> list[str]`, `_grounding_clause(f) -> str`.
- `to_markdown`/`to_html` public signatures UNCHANGED.

- [ ] **Step 1: Write the failing emit tests (both tiers)**

Add these tests to `core/tests/test_reports_emit.py` (append; keep the existing tests). They exercise the new row behavior directly on `ReportContent`:

```python
from f0_sectools_core.reports.content import (
    BlockKind, MetricCard, ReportContent, Section,
)
from f0_sectools_core.reports.emit import to_html, to_markdown
from f0_sectools_core.schema.findings import (
    Entity, EntityKind, Evidence, Finding, FindingType, Reference, Severity,
)


def _op_finding() -> Finding:
    return Finding(
        source="tenable", finding_type=FindingType.risk, severity=Severity.critical,
        title="3 internet-exposed critical vulnerabilities",
        evidence=[Evidence(key="cvss", value="9.8"), Evidence(key="exposed_assets", value="3")],
        references=[Reference(type="mitre", id="T1190"), Reference(type="cve", id="CVE-2026-1")],
    )


def _op_content() -> ReportContent:
    return ReportContent(
        persona="detection_engineer", language="en", tier="operational",
        title="Security Operations Report", subtitle="Prepared for Detection Engineering",
        sections=[Section(BlockKind.finding_table, "Findings", "operational",
                          findings=[_op_finding()])],
    )


def _exec_content() -> ReportContent:
    f = Finding(source="intune", finding_type=FindingType.risk, severity=Severity.high,
                title="Device compliance gap",
                entity=Entity(kind=EntityKind.tenant, id="t1", name="39% of devices non-compliant"))
    return ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Executive Risk Briefing", subtitle="Prepared for the CISO",
        sections=[Section(BlockKind.finding_rollup, "Top risks", "executive", findings=[f])],
    )


def test_operational_rows_carry_source_mitre_and_all_evidence_md():
    md = to_markdown(_op_content())
    assert "**[CRITICAL]** 3 internet-exposed critical vulnerabilities — tenable · ATT&CK: T1190" in md
    assert "cvss: 9.8" in md
    assert "exposed_assets: 3" in md          # unbounded — every evidence pair present


def test_operational_rows_carry_evidence_and_mitre_html():
    html = to_html(_op_content())
    assert "finding--critical" in html
    assert "ATT&CK: T1190" in html
    assert "finding__evidence" in html
    assert "cvss: 9.8" in html


def test_executive_rows_are_compact_no_evidence_no_mitre():
    md = to_markdown(_exec_content())
    html = to_html(_exec_content())
    # one grounded line, using the entity name as the clause
    assert "**[HIGH]** Device compliance gap — 39% of devices non-compliant" in md
    # executive tier shows neither evidence keys nor ATT&CK
    assert "ATT&CK" not in md and "ATT&CK" not in html
    assert "finding__evidence" not in html


def test_no_chat_aggregate_heading_leaks_into_report():
    # The old render_findings(ciso) path injected a "## Security posture rollup"
    # heading inside the section body; report-owned rows must not.
    assert "Security posture rollup" not in to_markdown(_exec_content())
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest core/tests/test_reports_emit.py -k "operational or executive or aggregate" -v`
Expected: FAIL — current emit renders the chat aggregate (no `ATT&CK:`/`finding__evidence`, and the CISO path emits "Security posture rollup").

- [ ] **Step 3: Add the row helpers to `emit.py`**

Add these helpers (place them near `_sorted`):

```python
def _sev_tag(f: Finding) -> str:
    return f.severity.value.upper()


def _mitre_ids(f: Finding) -> list[str]:
    return [r.id for r in f.references if r.type == "mitre"]


def _grounding_clause(f: Finding) -> str:
    """One short grounding phrase for an executive row: entity name, else the
    first evidence key: value, else empty."""
    if f.entity is not None and f.entity.name:
        return f.entity.name
    if f.evidence:
        return f"{f.evidence[0].key}: {f.evidence[0].value}"
    return ""
```

- [ ] **Step 4: Add `_md_findings` and `_html_findings` to `emit.py`**

```python
def _md_findings(findings: list[Finding], tier: str) -> list[str]:
    lines: list[str] = []
    for f in _sorted(findings):
        if tier == "executive":
            clause = _grounding_clause(f)
            suffix = f" — {clause}" if clause else ""
            lines.append(_r(f"- **[{_sev_tag(f)}]** {f.title}{suffix}"))
        else:
            mitre = _mitre_ids(f)
            meta = f.source + (f" · ATT&CK: {', '.join(mitre)}" if mitre else "")
            lines.append(_r(f"- **[{_sev_tag(f)}]** {f.title} — {meta}"))
            lines.extend(_r(f"  - {ev.key}: {ev.value}") for ev in f.evidence)
    return lines


def _html_findings(findings: list[Finding], tier: str) -> list[str]:
    out: list[str] = []
    for f in _sorted(findings):
        sev = _SEV_CLASS.get(f.severity.value, "info")
        parts = [
            f'<div class="finding finding--{sev}">',
            f'<div class="finding__title">[{_e(_sev_tag(f))}] {_e(f.title)}</div>',
        ]
        if tier == "executive":
            clause = _grounding_clause(f)
            if clause:
                parts.append(f'<div class="finding__meta">{_e(clause)}</div>')
        else:
            mitre = _mitre_ids(f)
            meta = f.source + (f" · ATT&CK: {', '.join(mitre)}" if mitre else "")
            parts.append(f'<div class="finding__meta">{_e(meta)}</div>')
            parts.extend(
                f'<div class="finding__evidence">{_e(f"{ev.key}: {ev.value}")}</div>'
                for ev in f.evidence
            )
        parts.append("</div>")
        out.append("".join(parts))
    return out
```

- [ ] **Step 5: Rewire the finding branches + drop the chat-renderer dependency**

In `_md_body`, change its signature to drop `content` and replace the finding branch to call `_md_findings(s.findings, s.tier)`:

```python
def _md_body(s: Section) -> list[str]:
    if s.kind is BlockKind.metric_grid:
        return [f"- **{_r(m.label)}:** {_r(m.value)} ({_r(m.state)})" for m in s.metrics]
    if s.kind in (BlockKind.finding_rollup, BlockKind.finding_table):
        lines: list[str] = []
        if s.text.strip():
            lines.append(_r(s.text))
            lines.append("")
        if not s.findings:
            lines.append("_No findings in this window._")
        else:
            lines.extend(_md_findings(s.findings, s.tier))
        return lines
    if s.kind is BlockKind.open_questions:
        return [f"{i}. {_r(q)}" for i, q in enumerate(s.items, 1)]
    if s.kind is BlockKind.coverage:
        return [f"- {_r(item)}" for item in s.items] or [_r(s.text)]
    return [_r(s.text)]
```

In `_html_body`, drop `content` from the signature and replace the finding branch to call `_html_findings(s.findings, s.tier)`:

```python
    if s.kind in (BlockKind.finding_rollup, BlockKind.finding_table):
        out: list[str] = []
        if s.text.strip():
            out.append(f"<p>{_e(s.text)}</p>")
        if not s.findings:
            out.append('<p><em>No findings in this window.</em></p>')
        else:
            out.extend(_html_findings(s.findings, s.tier))
        return out
```

Update the two call sites: in `to_markdown` change `_md_body(s, content)` → `_md_body(s)`; in `to_html` change `_html_body(s, content)` → `_html_body(s)`.

Delete the now-unused `_finding_row` function, the `_persona` helper, and the imports `from f0_sectools_core.renderers import Persona, render_findings` (verify with `grep -n "render_findings\|_persona\|Persona\|_finding_row" core/f0_sectools_core/reports/emit.py` returning nothing after edits). Update the module docstring line "Finding bodies reuse the persona renderers so presentation stays DRY." → "Finding rows are report-owned and tier-aware, so Markdown and HTML stay in step."

- [ ] **Step 6: Add the evidence CSS class**

In `core/f0_sectools_core/reports/assets/report.css`, add after the `.finding__meta` rule:

```css
.finding__evidence { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 9pt; color: #555; margin-top: 1px; }
```

- [ ] **Step 7: Run the emit tests (new + existing)**

Run: `uv run pytest core/tests/test_reports_emit.py -v`
Expected: all pass. If an EXISTING assertion fails because it depended on the old chat-aggregate output (e.g. asserting "Security posture rollup" or "By severity:"), update it to the new row format — but do NOT weaken a redaction or structural assertion; if one looks like it's testing real behavior that the change legitimately alters, fix the assertion to the new correct output.

- [ ] **Step 8: Re-freeze the CISO golden and eyeball it**

Run the freeze snippet (same fixtures as the builder test), then READ the file:
```bash
uv run python -c "
import json, pathlib
from f0_sectools_core.reports import build_report
from f0_sectools_core.reports.content import MetricCard, ScopeMeta
from f0_sectools_core.schema.findings import Finding
FIX = pathlib.Path('core/tests/fixtures/reports')
findings = [Finding.model_validate(d) for d in json.loads((FIX/'findings_ciso.json').read_text())]
meta = ScopeMeta(generated_at='2026-07-24 14:22', tenant_label='Contoso', window_label='Trailing 7 days',
  platforms_queried=['defender','tenable','intune','purview','projectachilles','limacharlie'],
  findings_count=3, assessed=['Config hardening','Vulnerability exposure'],
  not_assessed=['Insider risk (not licensed)'], pillar_metrics=[MetricCard('Config hardening','62%','needs-work')])
out = build_report('ciso','en',(FIX/'narrative_ciso_en.md').read_text(),findings,meta)
(FIX/'golden_ciso_en.md').write_text(out.markdown)
print(out.markdown)
"
```
Confirm in the printed output: the "## Top risks" section now shows compact one-liners like `- **[CRITICAL]** 3 internet-exposed critical vulnerabilities — cvss: 9.8` (grounding from first evidence), the risk-framing prose still leads the section, there is NO `## Security posture rollup` heading anywhere, and no secrets/real identifiers. If it looks right, that file is the re-frozen golden. If it looks wrong, STOP and report NEEDS_CONTEXT with the output.

- [ ] **Step 9: Verify types, lint, and the full suite**

Run:
```bash
uv run pytest core/tests/test_reports_emit.py core/tests/test_reports_builder.py -v
uv run pytest -q
uv run mypy core/ servers/
uv run ruff check .
```
Expected: all pass, mypy + ruff clean. (`test_golden_ciso_en_frozen` now matches the re-frozen golden.)

- [ ] **Step 10: Commit**

```bash
git add core/f0_sectools_core/reports/emit.py core/f0_sectools_core/reports/assets/report.css core/tests/test_reports_emit.py core/tests/fixtures/reports/golden_ciso_en.md
git commit -m "feat(reports): report-owned tier-aware finding rows (evidence+MITRE, no chat-aggregate)"
# (append the two trailers)
```

---

### Task 2: Operational golden + builder-level tier assertions

**Files:**
- Create: `core/tests/fixtures/reports/findings_detection.json` (neutral; findings with evidence + MITRE refs)
- Create: `core/tests/fixtures/reports/narrative_detection_en.md`
- Create: `core/tests/fixtures/reports/golden_detection_en.md` (frozen dense-row output)
- Modify: `core/tests/test_reports_builder.py` (operational golden + tier assertions)

**Interfaces:**
- Consumes Task 1's emit output via `build_report`. No production code changes.

- [ ] **Step 1: Create the operational fixtures (neutral values only)**

`core/tests/fixtures/reports/findings_detection.json`:
```json
[
  {"source": "defender", "finding_type": "incident", "severity": "high",
   "title": "Suspicious PowerShell on web-01.corp.local",
   "evidence": [{"key": "device", "value": "web-01.corp.local"}, {"key": "account", "value": "CORP\\jsmith"}],
   "references": [{"type": "mitre", "id": "T1059"}]},
  {"source": "limacharlie", "finding_type": "hunt_result", "severity": "medium",
   "title": "Outbound beacon pattern to rare domain",
   "evidence": [{"key": "domain", "value": "rare.example.test"}, {"key": "count", "value": "42"}],
   "references": [{"type": "mitre", "id": "T1071"}, {"type": "mitre", "id": "T1571"}]}
]
```

`core/tests/fixtures/reports/narrative_detection_en.md`:
```markdown
## Executive Summary
Two detection signals stand out this window: a suspicious PowerShell execution and an outbound beaconing pattern.

## Risk Framing
The PowerShell execution warrants a tuning review; the beacon pattern is a hunting lead worth pivoting on.

## Open Questions
- Do our existing D&R rules already cover T1059 execution on managed endpoints?
- Should the rare-domain beacon become a standing detection or a one-off hunt?
```

- [ ] **Step 2: Write the builder-level tests**

Add to `core/tests/test_reports_builder.py`:

```python
def _detection_findings() -> list[Finding]:
    data = json.loads((FIX / "findings_detection.json").read_text())
    return [Finding.model_validate(d) for d in data]


def _op_scope() -> ScopeMeta:
    return ScopeMeta(
        generated_at="2026-07-24 14:22", tenant_label="Contoso",
        window_label="Trailing 7 days", platforms_queried=["defender", "limacharlie"],
        findings_count=2, assessed=["Detections"], not_assessed=[],
    )


def test_operational_report_renders_evidence_and_mitre():
    narrative = (FIX / "narrative_detection_en.md").read_text()
    out = build_report("detection-engineer", "en", narrative, _detection_findings(), _op_scope())
    md = out.markdown
    assert "ATT&CK: T1059" in md
    assert "ATT&CK: T1071, T1571" in md          # multiple techniques joined
    assert "device: web-01.corp.local" in md      # evidence rendered
    assert "account: CORP\\jsmith" in md


def test_ciso_report_has_no_evidence_or_mitre_rows():
    narrative = (FIX / "narrative_ciso_en.md").read_text()
    out = build_report("ciso", "en", narrative, _findings(), _scope())
    assert "ATT&CK" not in out.markdown           # executive tier stays compact


def test_golden_detection_en_frozen():
    narrative = (FIX / "narrative_detection_en.md").read_text()
    out = build_report("detection-engineer", "en", narrative, _detection_findings(), _op_scope())
    assert out.markdown == (FIX / "golden_detection_en.md").read_text()
```

(Reuse the existing `FIX`, `_findings`, `_scope`, and imports already at the top of the file — add `ScopeMeta`/`json` to the imports only if not already present.)

- [ ] **Step 3: Run to verify the two behavioral tests pass and the golden test fails**

Run: `uv run pytest core/tests/test_reports_builder.py -k "operational or no_evidence or detection" -v`
Expected: `test_operational_report_renders_evidence_and_mitre` and `test_ciso_report_has_no_evidence_or_mitre_rows` PASS; `test_golden_detection_en_frozen` FAILS (golden file doesn't exist yet).

- [ ] **Step 4: Freeze the operational golden and eyeball it**

```bash
uv run python -c "
import json, pathlib
from f0_sectools_core.reports import build_report
from f0_sectools_core.reports.content import ScopeMeta
from f0_sectools_core.schema.findings import Finding
FIX = pathlib.Path('core/tests/fixtures/reports')
findings = [Finding.model_validate(d) for d in json.loads((FIX/'findings_detection.json').read_text())]
meta = ScopeMeta(generated_at='2026-07-24 14:22', tenant_label='Contoso', window_label='Trailing 7 days',
  platforms_queried=['defender','limacharlie'], findings_count=2, assessed=['Detections'], not_assessed=[])
out = build_report('detection-engineer','en',(FIX/'narrative_detection_en.md').read_text(),findings,meta)
(FIX/'golden_detection_en.md').write_text(out.markdown)
print(out.markdown)
"
```
Confirm: dense rows with `— defender · ATT&CK: T1059`, evidence sub-bullets (`  - device: web-01.corp.local`), the risk-framing lead-in, open questions, provenance — and only neutral identifiers. If right, the file is the frozen golden.

- [ ] **Step 5: Full verify**

Run:
```bash
uv run pytest core/tests/test_reports_builder.py -v
uv run pytest -q
uv run ruff check .
```
Expected: all pass, ruff clean. (No production code changed in this task, so mypy is unaffected — but run `uv run mypy core/ servers/` anyway to be safe.)

- [ ] **Step 6: Commit**

```bash
git add core/tests/test_reports_builder.py core/tests/fixtures/reports/findings_detection.json core/tests/fixtures/reports/narrative_detection_en.md core/tests/fixtures/reports/golden_detection_en.md
git commit -m "test(reports): operational golden + tier assertions (evidence+MITRE present, absent for CISO)"
# (append the two trailers)
```

---

## Self-review checklist (author, before execution)

- Spec coverage: two-tier rows ✅ (Task 1), evidence+MITRE operational ✅ (Task 1/2), executive compact ✅ (Task 1), MD/PDF consistency via shared renderers ✅ (Task 1), stray-heading removal ✅ (Task 1 Step 8/test), goldens ✅ (Task 1 CISO re-freeze + Task 2 operational).
- No placeholders: all steps carry complete code.
- Type consistency: `_md_findings`/`_html_findings` take `(list[Finding], str)`; `_md_body`/`_html_body` drop `content`; call sites updated; unused imports removed.

## Out of scope

Charts/gauges; changing the gather layer, the chat persona renderers, or the findings schema; per-finding evidence truncation.
