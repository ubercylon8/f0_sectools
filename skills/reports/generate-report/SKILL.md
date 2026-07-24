---
name: generate-report
description: Persona posture report (MD+PDF, EN/ES) from findings
version: 1.0.0
metadata:
  hermes:
    tags: [security, report, posture, ciso, deliverable]
    category: security
---

# Generate a Persona Posture Report

## When to Use

The operator wants a **shareable report** — a deliverable to open a conversation,
not a chat answer. Triggers: "generate my report", "build a CISO briefing",
"posture report I can send", "informe de postura". Produces Markdown (always) and
PDF (optional), in English or Spanish.

Pick the persona from the operator's role/lens:
- **ciso** — executive risk briefing (six-pillar posture, big numbers, restraint)
- **detection-engineer** — detection coverage + tuning questions
- **threat-hunter** — telemetry/incidents + hypothesis questions
- **security-engineer** — hardening backlog across identity/compliance/exposure

## Procedure

1. **Gather the findings** for the persona (read-only). For **ciso**, use the
   `roll-up-ciso-risk` skill's six pillars. Ground everything in what the tools
   actually return; a dark platform is "not assessed", never guessed.
2. **Author the narrative file** in the chosen language, using
   `references/narrative-template.md`. Fill three sections: `## Executive Summary`
   (the one-paragraph "so what"), `## Risk Framing` (per-risk notes), and
   `## Open Questions` (2–4 questions **for the operator to answer** — the
   conversation starter). Write only what the gathered findings support.
3. **Generate** (shell-capable runtimes): run
   `uv run python scripts/gen_report.py --persona <persona> --lang <en|es>
   --narrative <file> --window-hours <N> --tenant-label "<label>" --out <path> [--pdf]`.
   The script re-gathers the data deterministically (fresh, redacted) — your
   narrative supplies judgment, the script supplies the numbers.
4. **Hand back** the written path and a one-line summary. If the runtime has no
   shell, hand the operator the exact command to run.

## Pitfalls

- **Don't put numbers in the narrative.** The data sections come from the
  re-gather; the narrative is judgment (summary, framing, questions). A number
  you type is not grounded.
- **Open questions are for the operator, not rhetorical.** End with real
  decisions the operator must weigh (risk appetite, prioritization, blind spots).
- **PDF is optional.** If WeasyPrint isn't installed the script still writes the
  Markdown and prints an install hint; report that honestly.
- **One language per run.** Author the narrative in the same language you pass to
  `--lang`; the deterministic labels switch automatically.

## Verification

- The command prints `wrote <path>.md` (and `wrote <path>.pdf` with `--pdf`).
- The report ends with an **Open questions** section and a **Provenance** stamp.
- Any "not assessed" pillars name the dark platform explicitly.
