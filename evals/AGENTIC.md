# Multi-step (agentic) skill scorecard

Endpoint `http://localhost:11434/v1` · runs/scenario 3 · generated 2026-07-12

Each cell is **tool-coverage% / goal-reached%** for a model driving that skill's full procedure against deterministic mock tools. `err` = model/endpoint error; `–` = not run.

| Skill | GPT-OSS 20B | Qwen3 8B | Qwen3 4B | Qwen3.5 (9.7B) | Gemma 4 E4B | Gemma 4 12B | Granite 4 Tiny |
|---|---|---|---|---|---|---|---|
| defender-triage-incident | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% |
| intune-coverage-gap-review | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 0% | 67% / 0% | 100% / 100% | 100% / 100% |
| triage-incident-cross-platform | 100% / 0% | 100% / 100% | 80% / 100% | 60% / 0% | 100% / 33% | 100% / 100% | 40% / 0% |

## Speed & footprint

Median wall-clock to drive **one whole skill** end-to-end (multi-step loop against mock tools) and resident **VRAM** (Ollama `size_vram`). Local box, one model resident at a time — an operator's guide to picking a model for their hardware. Orthogonal to the correctness matrix above.

| Model | median s / skill | VRAM |
|---|---|---|
| GPT-OSS 20B | 11.6s | 11.8 GB |
| Qwen3 8B | 39.9s | 11.1 GB |
| Qwen3 4B | 52.6s | 5.1 GB |
| Qwen3.5 (9.7B) | 21.7s | 5.6 GB |
| Gemma 4 E4B | 14.4s | 3.3 GB |
| Gemma 4 12B | 34.2s | 8.1 GB |
| Granite 4 Tiny | 3.3s | 6.0 GB |

<!-- findings below: hand-annotated, preserved when the table is regenerated -->

## Findings

*(runs/scenario = 3; the multi-step loop is scored 3× per cell and averaged. Goal keywords
are synonym concept groups — a concept counts if any synonym appears — so phrasing variance
no longer fails a faithful answer.)*

**Single-platform skills are effectively solved.** Every model drives `defender-triage-incident`
(2 tools) and `intune-coverage-gap-review` (3 tools) at ~100% coverage, and most reach the goal
100%. Two persistent goal misses on intune: **Qwen3.5** (100% coverage / 0% goal — it calls all
three tools but its summary omits the stale/unencrypted concepts) and **Gemma 4 E4B** (67%
coverage — it also drops a tool). These are *synthesis* misses, not tool-selection misses, and
they survive the synonym check + 3 runs — a real, if narrow, weakness.

**The 5-tool cross-platform pivot separates the field on BOTH axes.** Coverage (stable) ranks the
models: GPT-OSS 20B / Qwen3 8B / both Gemmas call all 5 tools (100%), Qwen3 4B 80%, Qwen3.5 60%,
Granite 40%. At runs=3 the goal column now carries signal too: **Qwen3 8B, Qwen3 4B, and Gemma 4
12B reach the goal 100%**; Gemma 4 E4B 33%; GPT-OSS, Qwen3.5, and Granite 0%. Two things stand
out: **Qwen3 4B reaches the goal (100%) on only 80% coverage** — it synthesizes the key facts from
4 of 5 tools — while **GPT-OSS has 100% coverage but 0% goal**.

**Goal-reached is directional, not precise, for the hard skill — read coverage as the capability
metric.** The GPT-OSS 0% is a high-variance artifact, not incapacity: a diagnostic re-run produced
a complete synthesis hitting **all three** concepts (web-01, brute-force/T1110, risky/flagged), yet
its 3 sweep runs all missed one. The free-text synthesis of a 5-step chain varies run-to-run even
at temperature 0 (Ollama is not fully deterministic), so goal-reached stays noisy for high-variance
models even at runs=3, while **coverage% is stable and trustworthy**. Treat the cross-platform goal
column as "can it usually pull the whole picture together", not a precise score.

**Speed & footprint — the operator's model-selection guide** (10× spread):
- **Granite 4 Tiny** — **3.3s/skill, 6.0 GB** — the speed champion, but weakest on the long chain
  (40% coverage). The fast, light default for single-platform work.
- **Qwen3 thinking models pay a reasoning-token tax**: Qwen3 8B 39.9s, Qwen3 4B **52.6s** — 10×+
  slower — though Qwen3 4B is a light 5.1 GB and, notably, the most *reliable* cross-platform goal
  (100%).
- **Gemma 4 E4B** — lightest at **3.3 GB**, fast (14.4s), but the weakest synthesizer.
- **GPT-OSS 20B** — fast for its size (11.6s) and 100% coverage everywhere, but the biggest
  footprint (11.8 GB) and an unstable cross-platform goal.

**Deployment takeaway (sharpened by runs=3):** for single-platform skills, almost any model works —
pick on speed/VRAM (**Granite** or **Gemma 4 E4B**). For the multi-step cross-platform pivot,
**coverage + goal reliability favour Qwen3 8B / Qwen3 4B and Gemma 4 12B** over GPT-OSS here — a
result the single-turn scorecard (where GPT-OSS led) would never have surfaced.

> **Caveats.** Mock-driven (deterministic canned tool output, not live platforms), runs=3,
> temperature 0. Coverage% is stable; goal-reached is directional for the hard multi-step skill
> (high run-variance even at temp 0). Latency is median wall-clock per whole skill, one model
> resident at a time.
