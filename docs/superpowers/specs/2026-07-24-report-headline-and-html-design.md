# Report Headline Metrics + HTML Output — Design

**Date:** 2026-07-24 · **Status:** approved-pending-review · **Branch:** `feat/report-headline-html`

Two converging improvements to the shipped report engine, driven by a real
live-run finding: the "Posture at a glance" tiles rendered the whole metric
*sentence* at big-number size (giant wrapping text), because the metric value
fell back to the finding title. The fix — letting each pillar tool declare a
compact **headline** number — also sharpens the executive top-risk one-liners.
Alongside it, we make **HTML a first-class output** and overhaul the stylesheet
so both the standalone `.html` and the WeasyPrint PDF are well-proportioned.

Approved visual direction (via the visual companion): **Direction A — Executive
Brief** metric tiles (pillar label · one big compact number · state word · small
descriptor), and a single calm type scale for the whole report.

## Problem

- `report_gather._metric_from` sets each tile's `value` by looking up a guessed
  per-pillar evidence key (`_PILLAR_METRIC_KEY`: `secure_score_pct`,
  `critical_count`, …) that does **not** match what the tools actually emit
  (`current_score`/`max_score`, `critical`/`high`, …). It always falls back to
  the finding **title**, and the headline number (e.g. "90%") is often *derived*,
  not a raw evidence value at all. The CSS then renders that long title at 26pt →
  the giant wrapped tiles.
- The executive top-risk one-liner's grounding clause uses the *first* evidence
  pair, which is often not the decision-relevant number (`devices_total: 1507`).
- The engine already produces self-contained HTML (`to_html`) but the CLI throws
  it away — only Markdown and (optionally) PDF are written.

## Design

### 1. Headline evidence key (`headline`)

Each of the six CISO pillar tools emits one extra evidence entry,
`Evidence(key="headline", value="<compact phrase>")` — the compact,
decision-relevant number for the tile. Guideline: a short phrase, ≤ ~16 chars,
that reads well as a big tile value:

| Tool | source | headline (example) |
|---|---|---|
| `get_secure_score` | defender | `90%` |
| `get_defense_score` | projectachilles | `51% blocked` |
| `get_vulnerability_summary` | tenable | `263 critical` |
| `get_compliance_summary` | intune | `67% compliant` |
| `get_dlp_summary` | purview | `6 DLP alerts` |
| `get_org_overview` | limacharlie | `135 online` |

The tool already computes these numbers for its title; it now also exposes the
headline explicitly. This is a general enhancement (any consumer gets "the one
number"), not report-only. The exact phrasing lives with each tool.

### 2. `MetricCard.detail` (content IR)

Add `detail: str = ""` to `MetricCard` (`content.py`) — the small descriptor line
under the tile number. Populated with the finding's title (full context, small
type). Additive, defaulted.

### 3. Report layer prefers the headline

- **`report_gather._metric_from`** — value = the `headline` evidence value;
  `detail` = the finding title; state unchanged (from severity). Remove the
  broken `_PILLAR_METRIC_KEY` map. Fallback if a finding somehow lacks a
  `headline` (defensive): value = a short slice of the title, detail = title.
- **`emit._grounding_clause`** (executive one-liner) — prefer the `headline`
  value, but **skip it when it is already a substring of the title** (avoids
  "…(90%) — 90%"); then entity name; then the first non-`headline` evidence
  `key: value`; then empty.
- **Operational evidence rendering** (`_md_findings` / `_html_findings`) — skip
  the `headline` key when listing evidence sub-bullets (it is a tile hint, not
  detail). A small `_display_evidence(f)` helper returns evidence minus the
  `headline` entry. (Operational findings from non-pillar tools have no
  `headline`, so this is a no-op for them.)

### 4. Metric tile rendering (Direction A)

- **Markdown** — one line per pillar: `- **<big value>** — <label> (<state>) · <detail>`
  (or a compact equivalent; Markdown can't do the visual scale but stays
  readable and grounded).
- **HTML** — the Direction A tile: pillar label (small caps) · big number ·
  state word (colored) · small descriptor. The `metric__value` no longer holds a
  sentence, so the big-number size is correct.

### 5. Stylesheet overhaul (`assets/report.css`)

One stylesheet, both targets:
- A single calm **type scale** (title / section header / body / tile number /
  finding rows) replacing the current mixed 26/22/12/9pt jumble.
- **Screen**: a light page background + centered "document" card so the
  standalone `.html` reads like a report in a browser.
- **Print**: keep `@page` (A4, margins); the document card resets to full-bleed
  so the PDF is unchanged in structure, just re-proportioned.
- Metric tile styles for Direction A; finding rows keep their shipped structure,
  re-proportioned to the new scale.

### 6. HTML as a first-class output

`gen_report.py` always writes `<out>.html` (self-contained, the same source the
PDF renders from). Markdown still always written; PDF still `--pdf`. Print the
`.html` path. Update the workflows.md CLI note to mention the `.html` output.

## Components / files

- The six CISO pillar tools add a `headline` evidence entry + update their
  contract tests: `servers/defender-mcp` `get_secure_score`,
  `servers/projectachilles-mcp` `get_defense_score`, `servers/tenable-mcp`
  `get_vulnerability_summary`, `servers/intune-mcp` `get_compliance_summary`,
  `servers/purview-mcp` `get_dlp_summary`, `servers/limacharlie-mcp`
  `get_org_overview`.
- `core/f0_sectools_core/reports/content.py` — `MetricCard.detail`.
- `core/f0_sectools_core/reports/emit.py` — tile rendering (MD + Direction-A
  HTML), `_grounding_clause` prefers headline, `_display_evidence` skips
  `headline`.
- `core/f0_sectools_core/reports/assets/report.css` — the overhaul.
- `scripts/report_gather.py` — `_metric_from` uses `headline` + sets `detail`;
  drop `_PILLAR_METRIC_KEY`.
- `scripts/gen_report.py` — write `<out>.html`.
- Tests + goldens — re-freeze `golden_ciso_en.md` (tiles) and check
  `golden_detection_en.md` (evidence skip is a no-op there); emit + builder tile
  tests; the six tool tests; a `_display_evidence`/grounding test.
- `docs/user-guide/workflows.md` — note the `.html` output.

## Testing

Layer A (offline, CI):
- Each of the six pillar tools' contract test asserts a `headline` evidence entry
  with the expected shape.
- `_metric_from` (via a gather test) yields a compact value + a `detail`, not the
  full title, when a `headline` is present.
- Emit: the HTML metric tile renders `metric__value` = the compact headline (no
  sentence); `metric__detail` present; operational evidence rendering omits the
  `headline` key; `_grounding_clause` prefers headline and skips it when in-title.
- Re-frozen CISO golden (tiles) + unchanged detection golden; redaction still
  holds on all tile/evidence strings.
- mypy strict (core + servers) + ruff clean.

Layer B (operator-gated): regenerate the live CISO report (EN + ES) and eyeball
the HTML + PDF — the tiles show compact numbers, proportion is calm.

## Out of scope

- Charts/gauges (still v2).
- Screen-only richness that diverges from the PDF (interactive JS, etc.) — one
  stylesheet, both targets.
- Re-deriving metric **state** (the endpoint "strong" vs 94%-dormant nuance comes
  from finding severity in the tool; the descriptor carries the nuance) — noted
  as a possible later refinement, not this change.
- Persona-specific gathering (operational personas still gather the six pillars
  in v1) — unchanged here.
