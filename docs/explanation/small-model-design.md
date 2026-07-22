# Designing tools small models can drive

*Explanation — the thesis that makes f0_sectools different, the concrete design
rules it imposes, and the measurement loop that keeps them honest.*

## The thesis

Organizations should be able to run security-operations agents **on their own
infrastructure, with small open-weight models** — GPT-OSS (20B), Qwen3
(4B/8B), Gemma 4 — served locally via vLLM or llama.cpp. No telemetry, no
sensitive security data leaving the host, no dependency on a frontier cloud
API.

That constraint has a sharp consequence. Small local models are now genuinely
good at tool calling, but their reliability degrades in specific, documented
ways: mis-selection when many tools are registered, mangled nested arguments,
regressions under aggressive quantization, and silent accuracy loss when
context outgrows VRAM. **A tool can be functionally perfect and still fail
because the model cannot reliably call it.** So the tool contract — not the
model — is where the engineering effort goes.

The floor we design for: **a ~4–20B model at 8-bit quant**, not a frontier API.

## The rules

From [CLAUDE.md](../../CLAUDE.md#designing-tools-for-small-models), enforced in
code by `core/`:

| Rule | Why | Where it's enforced |
|---|---|---|
| **Flat argument schemas** — top-level scalars only (`host_id: str`, `severity_min: str`) | Nested/object args are the #1 source of mangled calls | Code review + eval; no server registers an object-valued param |
| **Short, closed enums** — `"low" \| "medium" \| "high" \| "critical"` | Free-form strings get invented; 40-value enums get mis-picked | `Literal[...]` types on tool signatures, so enums live in the advertised JSON schema, not prose |
| **≤ ~8 tools per server** | Tool-selection accuracy drops as the registry grows | Server design; sprawling platforms split across focused servers |
| **Descriptive parameter names** — `alert_id` not `id`, `time_window_hours` not `t` | The name is the model's primary cue | Code review |
| **Bounded, paginated output** | An unbounded dump blows the context window and silently degrades accuracy | `core/paging`: default page 25, hard max 100, truncation announced via a finding |
| **Deterministic reads** — same args, same shape | Models chain calls; shape drift breaks the chain | Contract tests |
| **Tool descriptions written for a model** — one sentence on *when* and *what* | The description is the routing function | Reviewed against eval misroutes (see below) |
| **No raw query languages without a guide rail** | Small models guess KQL field names wrong | Defender's guided `hunt` builds vetted KQL server-side; the custom-KQL tool exists but is disambiguated |

Shared input guards live once in `core/smallmodel/`: `scope_ok` (strict
bounded charset, 1–128 chars — every gated-write target), `search_ok`
(permissive read-side bound — length + no control characters).

## Measurement, not vibes

The rules above would rot if they were only prose. The `evals/` harness points
a **real local model** at a server's actual tool registry and measures
**callability**:

- **Tool-selection accuracy** — given a natural-language task, does the model
  pick the right tool?
- **Argument-filling success** — does it populate the args correctly, across
  N runs?
- **Composition** — the hard test: every server's tools registered at once.
  Does routing survive a many-tool registry?

Results are published in [`evals/SCORECARD.md`](../../evals/SCORECARD.md) as a
model × server matrix. As of the 2026-07-13 sweep (34 tools, six servers):
five of seven tested models drive **every server at 100%/100%**, and the full
combined registry is driven at up to 100% (Qwen3.5) with every model ≥ 90%.
A second harness ([`evals/AGENTIC.md`](../../evals/AGENTIC.md)) measures
whether a model can drive a whole *skill* — a multi-step playbook — not just a
single call.

**The contract:** if a tool passes its contract tests but scores poorly here,
**the tool's design is wrong** — simplify the schema; never lower the bar.

## The feedback loop, demonstrated

This is not theoretical; the eval has repeatedly changed the code:

- **Colliding descriptions found and fixed.** The combined eval showed
  cross-server misroutes between Defender's hunting tool and LimaCharlie's
  telemetry query, and among three "overview" tools. Five descriptions were
  rewritten ([design](../superpowers/specs/2026-07-11-tool-description-disambiguation-design.md));
  the misroutes dropped measurably.
- **Guessed KQL replaced by a guided tool.** Models invented Defender field
  names in raw KQL. The fix was a `hunt` tool that assembles vetted KQL
  server-side from flat args ([design](../superpowers/specs/2026-07-14-defender-guided-hunt-design.md)).
- **Unbounded reads caught in a live run.** A pi session surfaced a `get_all`
  pattern dumping full result sets; `core/paging` clamps landed everywhere
  ([design](../superpowers/specs/2026-07-14-bounded-output-and-tenable-plugin-assets-design.md)).
- **Cross-cutting hardening as a measured pass.** String-advertised enums,
  unbounded limits, and asymmetric read/write validation were fixed together,
  with the scorecard's argument-fill column as the success metric
  ([design](../superpowers/specs/2026-07-19-small-model-safety-hardening-design.md)).

New servers and tools added since the last sweep are **pending their scorecard
pass** — the claim discipline is that per-model numbers are only ever quoted
from an actual run.

## What we deliberately did not build

The official LimaCharlie MCP server exposes **278 tools**, write-capable, with
optional cloud-LLM assistance. It is excellent for frontier models — and it is
the exact opposite of this design point. f0_sectools exposes 6 curated
LimaCharlie tools instead, because 278 tools in a small model's registry is a
routing catastrophe, and because local-only + read-only-gated is the thesis.
Same platform, different contract — choose by which model you run.

## Running the eval yourself

```bash
# one server against your local endpoint
uv run python -m evals.run --server tenable \
    --base-url http://localhost:11434/v1 --model qwen3 --runs 3

# the composition test: every server's tools registered at once
uv run python -m evals.run --server all \
    --base-url http://localhost:11434/v1 --model qwen3 --runs 3

# the full model x server sweep (models.yaml) with scorecard output
uv run python evals/scorecard.py --base-url http://localhost:11434/v1
```

Task sets are YAML in `evals/<server>/tasks.yaml` — at least one task per tool,
enforced by `evals/test_eval_coverage.py`. Evals run locally against your GPU
box (never in CI — no creds, no GPU there); see
[runtime performance](../runtime-performance.md) for choosing a serving stack
and model.
