# Design: Disambiguate colliding tool descriptions (roadmap #2.5)

**Date:** 2026-07-11
**Status:** Approved (design), pending spec review
**Scope:** One small change — reword 5 tool descriptions; verify with the combined eval.

## Problem

The multi-server (combined-registry) eval on 2026-07-11 measured cross-platform tool
mis-selection when all 22 tools are registered at once (`evals/SCORECARD.md`). Two
collisions cost 2–7 points on the `all` column for every model except GPT-OSS 20B:

1. **Hunting pair.** `run_hunting_query` (Defender) and `query_telemetry` (LimaCharlie)
   both say *"Use for ANY hunt"* — they compete for every hunting prompt. Qwen3 8B routed
   Defender hunting prompts to `query_telemetry` (×3) and LimaCharlie prompts to Defender's
   `get_secure_score` (×3).
2. **Overview/health trio.** `get_secure_score` (Defender), `get_org_overview` (LimaCharlie),
   `get_fleet_health` (ProjectAchilles). `get_fleet_health` reads generic ("Test-agent fleet
   health") with **no platform anchor**; Granite routed a LimaCharlie prompt to it.

These are **tool-description defects, not model failures** — the fix is sharper, platform-
anchored descriptions.

## Approach

Small models route on keywords in the description. For each colliding tool: (a) name its
platform first, (b) use distinctive platform vocabulary, (c) drop the over-broad "ANY"
claim, and (d) add an explicit cross-reference — "for X, use `<other_tool>` instead" —
which is the strongest signal for telling a small model when *not* to pick a tool. No
schema changes; descriptions stay concise (small-model-safe).

Trade-off accepted: cross-references name a sibling tool, so a future rename could go stale
— but renames are rare and the eval would catch it; the disambiguation value outweighs it.

## The rewrites (5 descriptions in the server `@mcp.tool()` docstrings)

- **`run_hunting_query`** (`servers/defender-mcp/.../server.py`): anchor to Microsoft
  Defender / KQL over M365/Entra/Defender devices; "For LimaCharlie endpoint telemetry, use
  `query_telemetry` instead." Keep the KQL table hints + `| take 50`.
- **`query_telemetry`** (`servers/limacharlie-mcp/.../server.py`): anchor to LimaCharlie
  EDR sensor telemetry + presets; "For Microsoft Defender / KQL hunts, use
  `run_hunting_query` instead." Keep the preset list.
- **`get_secure_score`** (defender): "Microsoft Secure Score — Microsoft 365 / Defender
  *configuration-hardening* posture as a single %. Microsoft tenant config only."
- **`get_org_overview`** (limacharlie): add a clause — the **LimaCharlie EDR** deployment
  (endpoint sensors + detection rules), not Microsoft config or validation agents.
- **`get_fleet_health`** (projectachilles): "**ProjectAchilles** validation-agent fleet
  health — how many *breach-&-attack-simulation* agents are online/offline. Not endpoint
  sensors (LimaCharlie) or Microsoft posture."

## Not in scope (YAGNI / deliberate)

- **Eval task/probe prompts unchanged** — editing them to ease routing would game the eval.
- **Gated-write tools unchanged** — Gemma 4 12B's reluctance to call `isolate_host` is one
  model being cautious about a safety-gated action; that is acceptable (arguably desirable)
  behaviour, and making a model *more* eager to isolate hosts is the wrong direction.
- No `core/`, schema, or argument changes.

## Verification (the eval is the test)

1. Contract tests still pass (`uv run pytest`) — descriptions don't affect the mocked
   contract tests, but run them to confirm nothing broke.
2. Re-run the combined per-origin report at `runs=3` on the two models that misrouted:
   `uv run python -m evals.run --server all --base-url http://localhost:11434/v1 --model
   qwen3:8b-c40k --runs 3` and `--model granite4:tiny-h-c128k`. Confirm the `misrouted->`
   lines for the hunting and overview/health tools clear (or materially shrink). Record
   before/after in the commit.
3. Optionally re-sweep those two rows in `SCORECARD.md` (`--models qwen3:8b-c40k,granite4:tiny-h-c128k
   --date <today>`) so the published `all` column reflects the improvement.

## Files touched

| File | Change |
|---|---|
| `servers/defender-mcp/f0_defender_mcp/server.py` | reword `run_hunting_query`, `get_secure_score` docstrings |
| `servers/limacharlie-mcp/f0_limacharlie_mcp/server.py` | reword `query_telemetry`, `get_org_overview` docstrings |
| `servers/projectachilles-mcp/f0_projectachilles_mcp/server.py` | reword `get_fleet_health` docstring |
| `evals/SCORECARD.md` | (optional) refresh the two re-swept rows + note the fix |
