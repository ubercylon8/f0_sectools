# Report Finding Rows — Design (evidence + MITRE, two densities)

**Date:** 2026-07-24 · **Status:** approved-pending-review · **Branch:** `feat/report-finding-rows`

A follow-up polish to the shipped report engine (PR #67). Give report finding
sections a **report-specific row renderer**, used by **both** the Markdown and
HTML emitters, rendered at **two densities** by tier — so operational reports
carry the technical evidence + MITRE the spec promised, the executive report
keeps its restraint, and the Markdown/PDF outputs stop drifting.

## Problem (what shipped in v1)

`core/f0_sectools_core/reports/emit.py` renders finding sections inconsistently:

- **Markdown** calls `render_findings(s.findings, persona)` — the *chat* persona
  aggregate. For CISO that injects a stray `## Security posture rollup` heading
  *inside* the "Top risks" section, and every persona's aggregate has a different
  shape than the HTML.
- **HTML** (`_finding_row`) shows only `title` + `source · severity` — **no
  evidence, no MITRE technique refs**.
- `finding_rollup` (executive/CISO) and `finding_table` (operational) render
  identically in each emitter — the two-tier distinction is nominal.

`Finding` already carries the data: `evidence: list[Evidence{key, value}]` and
`references: list[Reference{type, id, url}]` where MITRE refs have
`type == "mitre"` (id = technique, e.g. `T1190`).

## Design

Stop reusing the chat persona aggregate for report findings. Add report-owned
row renderers in `emit.py` — one Markdown, one HTML — each **tier-aware** (the
section's `tier` is already on `Section.tier`). Both emitters render the same
structural content, so Markdown and PDF no longer drift, and the stray heading
disappears (we no longer call `render_findings`).

Redaction is unchanged: every string still goes through `_r` (Markdown) / `_e`
(HTML) exactly as today.

### Executive tier — `finding_rollup` (CISO), one line per finding

Restraint. The executive already gets the model's risk-framing paragraph and the
big-number posture grid above; each risk is one grounded line:

- **Markdown:** `- **[HIGH]** Device compliance gap — 39% of managed devices non-compliant`
- **HTML:** a `.finding .finding--high` row: severity tag + title + one grounding
  clause.

The grounding clause is the finding's `entity` name if present, else the first
evidence as `key: value` (e.g. `cvss: 9.8`), else omitted. **No evidence list,
no MITRE** at this tier.

### Operational tier — `finding_table`, dense per finding

The approved "SecOps dossier" density. Per finding:

```
[CRITICAL] 3 internet-exposed critical vulnerabilities
   tenable · ATT&CK: T1190, T1210
   cvss: 9.8 · exposed_assets: 3 · plugin: 148291
```

- Line 1: severity tag + title.
- Line 2 (meta): `source` + `ATT&CK: <technique ids>` when the finding has
  `type == "mitre"` references (omit the ATT&CK part when none).
- Line 3+: **all** evidence `key: value` pairs (unbounded — a report is a
  human-facing document, and the findings feeding it are already bounded by the
  gather layer's tool pagination). Omit if the finding has no evidence.

- **Markdown:** the title line as a `-` bullet, meta + evidence as indented
  sub-lines.
- **HTML:** the existing `.finding .finding--<sev>` color-bar block, with a
  `.finding__meta` line and an evidence sub-block (`key: value` per line).

### Where the two tiers are selected

`Section.tier` is `"executive"` for the CISO `finding_rollup` and `"operational"`
for the operational `finding_table` (already set by `sections.SECTION_MAPS`).
The row renderers branch on it; no new plumbing.

## Components

Changes are confined to one module + tests + goldens.

- **`core/f0_sectools_core/reports/emit.py`**
  - Replace the `render_findings(...)` call in `_md_body`'s finding branch with a
    new `_md_findings(findings, tier)` that renders per-tier rows.
  - Replace `_finding_row(f)` with `_html_findings(findings, tier)` (tier-aware;
    executive = compact, operational = dense with meta + evidence).
  - Add small helpers: `_mitre_ids(f) -> list[str]` (ids of `type=="mitre"`
    references) and `_grounding_clause(f) -> str` (entity name → first evidence
    `key: value` → "").
  - `render_findings` / `Persona` imports are dropped from `emit.py` if no longer
    used (the report no longer routes findings through the chat renderer).
- **`core/tests/test_reports_emit.py`** — assertions for both tiers (executive =
  one-liner, no evidence/MITRE; operational = evidence + `ATT&CK:` present),
  redaction still holds, and no `## Security posture rollup` heading appears.
- **`core/tests/fixtures/reports/`** — re-freeze `golden_ciso_en.md` (Top-risks
  becomes compact one-liners, stray heading gone). Add an operational fixture +
  golden (a `detection_engineer` or `security_engineer` report) whose findings
  carry evidence + a MITRE reference, freezing the dense rows.
- **`core/tests/test_reports_builder.py`** — a builder-level test that an
  operational report renders evidence + MITRE and the CISO report does not.

## Testing

Layer A (offline, CI):
- Emit-level: executive rows are one line and carry neither evidence nor
  `ATT&CK:`; operational rows carry every evidence pair and `ATT&CK: T…` when
  MITRE refs exist; a planted secret in evidence is still redacted in both
  emitters; the `## Security posture rollup` heading is absent.
- Golden re-freeze (CISO) + new operational golden, both byte-exact.
- Full suite + mypy(core/servers) strict + ruff stay green.

## Out of scope

- Charts/gauges (still v2).
- Changing the gather layer, the persona *chat* renderers (used elsewhere), or
  the findings schema.
- Per-finding evidence truncation (operator chose unbounded).
