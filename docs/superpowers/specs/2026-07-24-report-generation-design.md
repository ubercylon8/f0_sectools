# Report Generation — Design

**Date:** 2026-07-24 · **Status:** approved-pending-review

Generate professional, persona-shaped **security posture reports** as a
**deliverable to open a conversation** — grounded in real findings, authored
partly by the persona agent, exported to **Markdown and PDF**, in **English or
Spanish**, produced entirely **on the host** (no external calls, nothing leaves
the box — the repo thesis).

## Goal

An operator working in a persona asks for "my report." The persona agent
gathers the relevant posture, writes the narrative and the open questions in
its own words, and a deterministic engine renders a styled `report.md` +
`report.pdf`. The report ends with **open questions for the operator to
answer** — it is a starting point for a discussion, not a closed artifact.

Four persona reports, one shared engine:

| Persona | Tier | Gathers |
|---|---|---|
| **CISO** | Executive (restraint, big numbers) | the six-pillar risk rollup |
| **Detection engineer** | Operational (dense tables, MITRE) | Defender incidents+MITRE, LimaCharlie D&R coverage, PA weak techniques |
| **Threat hunter** | Operational | Defender guided hunt, LimaCharlie telemetry, incidents |
| **Security engineer** | Operational | Secure Score actions, Entra CA/privileged roles, Intune gaps, Tenable exposure |

## Key decisions (with rationale)

1. **Narrative model-authored, data deterministic.** The persona agent writes
   the executive summary, the per-risk framing, and the open questions
   (judgment). The data sections (scores, findings, coverage) are rendered by
   code from real findings — never transcribed by the model — so the
   never-fabricate rule holds. (Rejected: fully-templated report — flat, generic
   open questions; fully model-authored document — loses grounding.)
2. **CLI + core builder + skill (not an MCP tool).** A report is a file
   deliverable and a deliberate action, not a chat query. The MCP servers stay
   thin; `gen_report.py` **re-gathers findings** via the servers' own tool
   functions so the numbers are code-sourced, fresh, and redacted. (Rejected: a
   `generate_report` MCP tool — a fat cross-platform server against the
   thin-server rule, plus a large free-text narrative arg.)
3. **One design system, two densities.** Executive tier (CISO) and Operational
   tier (the other three) share brand, typography, and the severity palette;
   they differ in finding density and technical detail. **Chart-free in v1**
   (typography + severity color); charts/gauges are optional v2 polish (avoids a
   plotting dependency).
4. **PDF via WeasyPrint.** HTML/CSS → PDF in pure Python — no headless browser,
   no system LaTeX, no external calls. Natural partner to the Markdown-emitting
   renderers. Optional extra (`f0-sectools-core[reports]`) so platform servers
   stay lean. Markdown is always produced; PDF requires the extra.
5. **EN + ES.** Language is a report parameter: it selects an EN/ES string
   table for the deterministic labels, and instructs the agent to author the
   narrative in that language (the persona prompts already say "reply in the
   user's language").
6. **All four personas in the first pass.** The engine is shared; per-persona
   cost is section config + gathering. (Operator chose completeness over a
   CISO-first staged delivery.)

## Report anatomy

The approved CISO (executive-tier) flow, top to bottom:

1. **Cover** *(deterministic)* — brand, title, prepared-for, scope
   (tenant · window · "generated locally by f0_sectools").
2. **Executive summary** *(model)* — the one-paragraph "so what".
3. **Posture at a glance** *(deterministic)* — the six pillars as restrained
   big numbers with a one-word state.
4. **Top risks** *(model-ranked, grounded)* — ranked by real severity this
   window; each line's number traces to a finding.
5. **Scope & coverage** *(deterministic)* — what is and isn't assessed
   (unlicensed / unconnected platforms named — the graceful-partial principle
   from the rollup skill, surfaced).
6. **Open questions** *(model)* — 2–4 questions **for the operator to answer**;
   the conversation-starter.
7. **Provenance** *(deterministic)* — generation stamp, platforms queried,
   findings count, redaction + no-external-calls note.

Operational-tier reports reuse cover / exec-summary / coverage / open-questions
/ provenance and swap the middle (3–4) for dense finding tables (severity
color-bars), technical evidence, and MITRE mapping — with persona-shaped open
questions (tuning for detection, hypothesis for hunt, hardening backlog for
security engineering).

## Components

### `core/reports/` — deterministic engine (model-free)

- **`content.py`** — a structured `ReportContent` model: ordered sections, each
  either a narrative block (agent prose, redacted) or a data block (findings /
  pillar metrics, rendered from real findings). One model, two emitters below —
  so MD and PDF never drift.
- **`builder.py`** — `build_report(persona, language, narrative, findings,
  scope_meta) -> ReportOutput` where `ReportOutput` carries `markdown: str` and
  `html: str`. Assembles `ReportContent` from the per-persona section map, the
  gathered findings, and the parsed narrative; emits Markdown and HTML.
- **`pdf.py`** — `to_pdf(html: str) -> bytes` via WeasyPrint + the CSS theme.
  Import-guarded: if WeasyPrint is absent, raise a clear "install
  `f0-sectools-core[reports]`" error; MD generation never depends on it.
- **`theme.py`** / `assets/report.css` — the two-tier design system (brand
  tokens, print `@page` layout, severity colors, tier variants).
- **`i18n.py`** — `LABELS: dict[Lang, dict[str, str]]` for every deterministic
  string; `Lang = Literal["en", "es"]`. A test asserts key-parity across
  languages (no missing translation).
- **`sections.py`** — `SECTION_MAPS: dict[Persona, list[SectionSpec]]` — order,
  tier, and which finding group feeds each data section.
- Reuses `core/renderers/` persona renderers for finding-body rendering.
- All output passes `core/redaction/` (narrative prose included).

### `scripts/gen_report.py` — CLI

```
uv run python scripts/gen_report.py \
  --persona {ciso,threat-hunter,detection-engineer,security-engineer} \
  --lang {en,es} --narrative <path> --window-hours <N> \
  --out <basepath> [--pdf]
```

Re-gathers findings by importing and calling the servers' `tools.py` functions
directly (reusing `core` clients + the per-platform `.env`) — no MCP round-trip.
A dark platform (missing creds/permission) degrades to a posture finding →
rendered as "not assessed", the report still generates. Writes `<out>.md` and,
with `--pdf`, `<out>.pdf`. Prints the paths.

### `skills/reports/generate-report` — one parametrized skill

Per-persona guidance in the body + a `references/narrative-template.md`. Drives
the agent: (1) gather the persona's findings (CISO → the rollup skill); (2)
author the narrative file — exec summary, per-risk framing, open questions — in
the chosen language, grounded strictly in what was gathered; (3) run
`gen_report.py` (shell-capable runtimes) or hand the operator the exact command.
Refers to tools by base name; wired into the persona prompts across runtimes and
the opencode symlink farm (drift-guarded).

## Data flow

```
operator (in persona) asks for a report
  → generate-report skill
    → agent gathers findings (tools / rollup)
    → agent writes narrative.md (summary, risks, open questions) in {lang}
    → gen_report.py --persona --lang --narrative --window-hours --out
        → re-gathers findings deterministically (fresh, redacted)
        → builder → ReportContent → markdown + html
        → (--pdf) WeasyPrint(html + css) → pdf bytes
        → writes report.md (+ report.pdf)
  → agent reports the path + a one-line summary
```

## Narrative handoff format

The agent writes a small Markdown file with fixed `##` section headers the
builder parses: `## Executive Summary`, `## Risk Framing` (optional per-risk
notes keyed by a finding tag), `## Open Questions` (a list). Missing optional
sections degrade gracefully (the builder falls back to a deterministic stub).
Keeps the model↔code contract simple and inspectable.

## Error handling & guarantees

- **Grounded:** data sections render only from re-gathered findings; the model
  cannot inject a number into a data section.
- **Redacted:** every emitter runs content through `core/redaction/`, narrative
  included.
- **Graceful partial:** a dark platform → "not assessed"; the report always
  generates something honest.
- **Local-only:** re-gather hits only the operator's configured platforms; PDF
  is local. No telemetry.
- **PDF optional:** MD always works; PDF asks for the extra if missing.

## Testing

Layer A (offline, CI):
- Golden-file **Markdown** per persona (a fixed findings + narrative fixture →
  expected MD), for **both languages**.
- `i18n` key-parity (EN and ES define the same keys).
- Section-map correctness (each persona's sections present, in order, right tier).
- Redaction of a secret planted in both a finding and the narrative.
- PDF smoke: `to_pdf(html)` returns bytes starting with `%PDF` (WeasyPrint
  present in the dev extra).

Layer B (live, operator-gated): generate a real **CISO** report EN + ES against
the tenant; eyeball the PDF; confirm "not assessed" pillars render correctly.

## Dependencies

- `weasyprint` (optional extra `[reports]`). No always-on new dependency for the
  servers.
- No plotting library in v1.

## Out of scope (v1)

- Charts / gauges (v2 polish).
- Scheduled / periodic reporting and trend history (on-demand snapshots only).
- Report storage / diffing across runs.
- Emailing or uploading the report anywhere (it writes to disk; distribution is
  the operator's).
