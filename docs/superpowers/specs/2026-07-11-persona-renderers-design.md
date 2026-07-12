# Design: Persona renderers (`core/renderers/`)

**Date:** 2026-07-11
**Status:** Approved (design), pending spec review
**Scope:** One implementation plan — build the planned-only `core/renderers/` presentation layer.

## Problem

f0_sectools' thesis is "one structured finding, many audiences." The findings schema
(`core/schema/findings.py`) is the single output contract; CLAUDE.md promises the same
finding is *rendered differently* per audience (SOC analyst, security engineer, CISO,
threat hunter) via `core/renderers/`. That module is a placeholder today — the only
`__init__.py` docstring, no code. The four personas exist as **agent behaviour** (prompt
"modes" / Hermes personalities) but there is no **deterministic text renderer**: today the
model itself free-forms the human-facing prose from the finding JSON. This design builds the
missing deterministic layer.

## Two persona layers — do not confuse them

- **Agent persona** (exists today): a behavioural lens in the system prompt / Hermes
  `agent.personalities`. Shapes the *whole model response* — which tools/skills it favours,
  how it frames things. Runs *in the model*. Remains the primary mechanism for chat.
- **Renderer** (this design): a deterministic Python function `Finding → text`. Same input →
  same output, zero token cost, no model involved. "Optional polish" per CLAUDE.md.

They **compose**: a renderer persona name maps 1:1 to an agent persona mode, so "switch to
detection engineer" can shape both behaviour and rendered text consistently.

## Consumer & boundary decisions (locked in brainstorming)

- **Consumer:** a **Python-side library**. Callers import and call it; its output **never
  enters model context**. First real consumer: the live-smoke scripts (a `--persona` flag).
  Not an MCP tool (would violate ≤8-tools and require passing findings back as a nested arg),
  not a server render-boundary injection (would touch the model's input and risk context bloat).
- **Entry points:** both `render_finding(finding, persona)` and `render_findings(findings,
  persona)`. The collection renderer is where persona shaping is most visible (CISO aggregate).
- **Persona set:** **five**, matching the agent-persona modes 1:1 — `soc_analyst`,
  `security_engineer`, `ciso`, `threat_hunter`, `detection_engineer`. (CLAUDE.md's renderer
  list currently names four; this design updates it 4→5 so renderer personas and agent
  personas stay symmetric.)
- **Output format:** Markdown text — reads fine raw in a terminal, is the repo's doc lingua
  franca.
- **Redaction:** every rendered string passes through the existing `redaction.redact_text`
  before return — defense-in-depth at the presentation boundary (Critical Rule 3), reusing
  core redaction rather than reimplementing it (Critical Rule 6).
- **No schema change.** `core/schema/findings.py` is untouched (Critical Rule 4).

## Architecture — template-method base + per-persona subclasses

```
core/f0_sectools_core/renderers/
  __init__.py    # public API: render_finding, render_findings, Persona, get_renderer
  base.py        # Persona(StrEnum); Renderer base class (template methods + shared helpers)
  personas.py    # 5 concrete subclasses + REGISTRY {Persona: Renderer}
core/tests/test_renderers.py   # contract tests (mirrors existing core test layout)
```

Chosen over (B) a data-driven persona config table — the aggregation differences (per-incident
list vs severity rollup vs chronological timeline vs MITRE grouping) are *behaviour*, not data,
and don't fit a table without smuggling code back in — and (C) one flat function per persona,
which duplicates the shared evidence/reference formatting five times (violates DRY).

### `base.py`

- **`Persona(StrEnum)`** — `soc_analyst`, `security_engineer`, `ciso`, `threat_hunter`,
  `detection_engineer`. Values match the agent-persona mode names.
- **`Renderer`** base class implementing the template methods and shared helpers:
  - `render_finding(finding) -> str` and `render_findings(findings) -> str` — the public
    template methods; both end by returning `redact_text(rendered)`.
  - Shared helpers: `_severity_tag(sev)` (uppercase label), `_entity_str(entity)`
    (`kind: name (id)`, or `"unspecified target"` when `entity is None`), `_evidence_lines(f)`
    (`- key: value` list; empty when no evidence), `_reference_str(ref)`
    (`[type:id](url)`; a `mitre` type with no url still shows `mitre:T1110`),
    `_sort_by_severity(findings)` (`critical>high>medium>low>info`, stable), and
    `_mitre_refs(f)` (references where `type == "mitre"`).
  - Overridable hooks (default impls on the base, personas override): `_finding_body(f)` and
    `_aggregate(findings)`.
- Severity order constant: `critical=0, high=1, medium=2, low=3, info=4` (lower sorts first).
- `observed_at` sorting uses the ISO string directly (ISO-8601 sorts lexicographically);
  findings with `observed_at is None` sort last, stably.

### `personas.py` — the five subclasses

| Persona | Single finding leads with | List / `_aggregate` strategy |
|---|---|---|
| `soc_analyst` (default) | severity-tagged title → entity → evidence ("What happened") → **Next step** (`recommended_action.summary` + `gated_action` name) | per-incident, ordered severity-desc then `observed_at`, under a `N findings (X critical, Y high…)` header |
| `security_engineer` | the gap + **the fix** (`recommended_action` as remediation), `source`, references | grouped by `source` then `finding_type`, biased to `misconfig`/`posture`, as a `- [ ] <fix>` **remediation checklist** |
| `ciso` | terse one risk line (severity · title · entity), **no evidence** | **rollup** — counts by severity, counts by source, top few critical/high titles, one-line posture statement; no raw evidence |
| `threat_hunter` | `observed_at` prominent, entity as **pivot**, evidence as IOCs, MITRE refs | sorted `observed_at` **ascending into a timeline** (`observed_at — title (entity)`), entities surfaced as pivots, IOC findings highlighted |
| `detection_engineer` | **MITRE mapping first** (`mitre` refs), then title/severity + detection `source` | organized **by MITRE technique**; findings with no MITRE ref flagged **`unmapped`** (coverage gap) |

- **`REGISTRY: dict[Persona, Renderer]`** — one instance per persona (renderers are stateless).
- **`get_renderer(persona: Persona | str) -> Renderer`** — coerces a `str` to `Persona`;
  unknown value raises `ValueError` (deterministic, no silent fallback).

### `__init__.py` — public API

```python
render_finding(finding: Finding, persona: Persona | str = Persona.soc_analyst) -> str
render_findings(findings: list[Finding], persona: Persona | str = Persona.soc_analyst) -> str
```

Both resolve the persona via `get_renderer` and delegate. Default persona `soc_analyst`
(matches the portable prompt's default mode). Re-exports `Persona` and `get_renderer`.

## Robustness / "error handling"

Input is already-validated Pydantic (no live API here), so robustness means **never raising
on a sparse finding**:

- `entity is None` → `"unspecified target"`.
- empty `evidence` → the "what happened" block is omitted, not left as a dangling header.
- `recommended_action is None` → no "next step" line.
- no `mitre` reference → `detection_engineer` marks the finding `unmapped`; other personas
  simply render no references.
- empty `findings` list → a short "No findings." line per persona, never an index error.

No rendered output contains the literal `"None"`.

## Testing

`core/tests/test_renderers.py`, pure `pytest`, deterministic, no model/network. Fixtures: a
*rich* finding (all fields incl. `entity`, `evidence`, `recommended_action` with
`gated_action`, a `mitre` reference, `observed_at`), a *sparse* finding (only required fields),
and a *mixed list* (varied severities/sources/timestamps, some with MITRE refs, some without).

- **Robustness (parametrized over all 5 personas):** `render_finding(sparse)` and
  `render_findings(mixed)` never raise, return non-empty text, contain no literal `"None"`.
- **Persona-distinctiveness:**
  - `ciso` list contains severity **counts** and **not** a raw evidence value.
  - `threat_hunter` list is **timeline-ordered** (earlier `observed_at` appears before later).
  - `detection_engineer` list contains **`unmapped`** for a MITRE-less finding and the
    technique id for a mapped one.
  - `soc_analyst` single contains the **next step** (`recommended_action.summary` + gated
    action name).
  - `security_engineer` list contains **checklist** markers (`- [ ]`).
- **Registry/coercion:** all 5 `Persona` values resolve via `get_renderer`; `"ciso"` (str)
  coerces; unknown `"cto"` raises `ValueError`; default persona is `soc_analyst`.
- **Redaction net (Rule 3):** a finding whose evidence value contains a secret-pattern token
  renders **redacted** — proves the final `redact_text` pass runs.
- **Determinism:** same input rendered twice → byte-identical output.

## First consumer (reference wiring)

`scripts/live_smoke_defender.py` gains an optional `--persona <name>` flag that, when passed,
**additionally** prints the rendered view after the raw JSON. **Non-destructive:** default
behaviour stays the raw redacted JSON dump that live-validation depends on (raw field-shape
inspection is the smoke script's whole purpose; replacing it would defeat that). One reference
consumer only (YAGNI); the same one-liner drops into the other four smoke scripts later.

## Out of scope (YAGNI)

- No server render-boundary injection, no MCP render tool (see consumer decision above).
- No wiring into all five smoke scripts, no new standalone report CLI — one reference consumer.
- No `core/schema` change, no new dependency (Markdown is plain strings; no templating engine).
- No HTML/ANSI-colour output — Markdown text only.

## Files touched

| File | Change |
|---|---|
| `core/f0_sectools_core/renderers/__init__.py` | replace placeholder — public API + re-exports |
| `core/f0_sectools_core/renderers/base.py` | new — `Persona` enum, `Renderer` base + helpers |
| `core/f0_sectools_core/renderers/personas.py` | new — 5 subclasses + `REGISTRY` + `get_renderer` |
| `core/tests/test_renderers.py` | new — contract tests |
| `scripts/live_smoke_defender.py` | add optional `--persona` flag (non-destructive) |
| `CLAUDE.md` | renderer list 4→5 (add `detection_engineer`); note renderer↔agent-persona 1:1 |
| `core/README.md` | renderers row: note the 5 personas + public API |
