# Multi-step (agentic) skill scorecard

Endpoint `http://localhost:11434/v1` · runs/scenario 1 · generated 2026-07-12

Each cell is **tool-coverage% / goal-reached%** for a model driving that skill's full procedure against deterministic mock tools. `err` = model/endpoint error; `–` = not run.

| Skill | GPT-OSS 20B | Qwen3 8B | Qwen3 4B | Qwen3.5 (9.7B) | Gemma 4 E4B | Gemma 4 12B | Granite 4 Tiny |
|---|---|---|---|---|---|---|---|
| defender-triage-incident | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% |
| intune-coverage-gap-review | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 0% | 67% / 0% | 100% / 100% | 100% / 100% |
| triage-incident-cross-platform | 100% / 0% | 100% / 0% | 80% / 0% | 60% / 0% | 100% / 0% | 100% / 0% | 40% / 0% |

## Speed & footprint

Median wall-clock to drive **one whole skill** end-to-end (multi-step loop against mock tools) and resident **VRAM** (Ollama `size_vram`). Local box, one model resident at a time — an operator's guide to picking a model for their hardware. Orthogonal to the correctness matrix above.

| Model | median s / skill | VRAM |
|---|---|---|
| GPT-OSS 20B | 17.4s | 11.8 GB |
| Qwen3 8B | 43.0s | 11.1 GB |
| Qwen3 4B | 46.1s | 5.1 GB |
| Qwen3.5 (9.7B) | 25.9s | 5.6 GB |
| Gemma 4 E4B | 19.8s | 3.3 GB |
| Gemma 4 12B | 31.9s | 8.1 GB |
| Granite 4 Tiny | 4.8s | 6.0 GB |

<!-- findings below: hand-annotated, preserved when the table is regenerated -->

## Findings

**Single-platform skills are solved.** Every model drives `defender-triage-incident`
(2 tools) and `intune-coverage-gap-review` (3 tools) at ~100% coverage, and mostly
reaches the goal. The two goal misses — Qwen3.5 and Gemma 4 E4B on the intune skill —
are the coarse **conjunctive keyword** check at `runs=1` (the answer summarised the gaps
but didn't echo every keyword), not a failure to drive the tools.

**The 5-tool cross-platform skill is the frontier — and coverage is where models
separate.** Driving the full Defender→Entra→LimaCharlie→ProjectAchilles pivot, tool
**coverage** splits the field: GPT-OSS 20B, Qwen3 8B, Gemma 4 E4B, and Gemma 4 12B call
all 5 required tools (100%); Qwen3 4B 80%; Qwen3.5 60%; **Granite 4 Tiny drops to 40%** —
fast, but it drops pivots on the long chain. This is the orchestration gap the single-turn
scorecard (which showed 96–100% for these models) **cannot see**: picking the right tool
in isolation ≠ carrying a 5-step chain to completion.

**Goal-reached at `runs=1` is NOT a reliable read on the hard skill — read coverage
instead.** The cross-platform `goal` column is 0% across the board, but that is a
measurement artifact, not a verdict: a diagnostic re-run of GPT-OSS on this scenario
produced a complete, correct synthesis that hit **all three** goal keywords (`web-01`,
`T1110`, `risky`) — yet its sweep cell reads 0%, because that single run's answer missed a
keyword (Ollama is not fully deterministic at temperature 0 across a multi-turn loop). So
`goal-reached` needs `runs≥3` to stabilise (as the single-turn scorecard already does for
notable cells); at `runs=1`, **coverage%** is the trustworthy capability signal.

**Speed & footprint — the operator's model-selection guide.** The correctness numbers hide
a 10× spread in cost:
- **Granite 4 Tiny** is the speed champion — **4.8s/skill, 6.0 GB** — but weakest on the
  cross-platform chain (40% coverage). Ideal as a fast default for single-platform work.
- The **Qwen3 thinking models pay a heavy reasoning-token tax** on multi-step: Qwen3 8B and
  Qwen3 4B are **43–46s/skill** (4–10× slower), despite Qwen3 4B's small 5.1 GB footprint.
- **Gemma 4 E4B** is the lightest (**3.3 GB**) and drives all three skills' tools at ≥67%.
- **GPT-OSS 20B** leads the hard skill (100% coverage) at a moderate **17.4s** but the
  biggest footprint (**11.8 GB**).

The two-tier deployment story holds and sharpens: **Granite as the fast, light default for
single-platform skills; GPT-OSS 20B for the multi-step cross-platform pivots** where the
extra capability (and VRAM) earns its keep.

> **Caveats.** Mock-driven (deterministic canned tool output, not live platforms), `runs=1`,
> temperature 0. Coverage% is stable; goal-reached needs `runs≥3`. Latency is median
> wall-clock per whole skill on this local box, one model resident at a time.
