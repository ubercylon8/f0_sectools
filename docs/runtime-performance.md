# Runtime & model performance — choosing a deployment

f0_sectools is built to run **on your own infrastructure with small, open-weight local
models** (no telemetry, no data off-box). This guide distills our benchmarks into two
operator decisions: **which serving runtime** and **which model** — and shows *why*, with
numbers you can reproduce.

> **Read the numbers as patterns, not absolutes.** Everything below was measured on a single
> box (16 GB GPU, Qwen3-4B) with our eval harness. The exact latencies are hardware/model/config
> specific; the **patterns** (and the ordering) generalize, and **configuration moves performance
> 2–30× more than the runtime name does.** Re-measure on your hardware — the harness makes it easy
> ([Reproduce](#reproduce-on-your-hardware)).

## TL;DR — the decision tables

**Runtime** (how you serve the model):

| Your situation | Runtime | Why |
|---|---|---|
| Single / few users, lowest latency, lightest footprint | **llama.cpp** (direct, `-ngl 99`) | Fastest sequential (~2.4× Ollama), Q4-light (~5 GB). Costs more manual setup. |
| Many concurrent analysts / agents | **vLLM** | Best throughput under load (continuous batching), predictable latency. Costs fp16 VRAM. |
| Balanced self-host | **llama.cpp `--parallel`** | Light Q4 footprint **and** real batching — the "best of both". |
| Dev / prototyping / easiest ops | **Ollama** | Simplest to run. But a ~2.4× sequential latency tax and serial-by-default (`OLLAMA_NUM_PARALLEL=1`). |

On a **16 GB GPU, run one runtime per box** — vLLM reserves GPU memory up front and will
starve a co-resident Ollama/llama.cpp into CPU offload.

**Model** (which weights to drive the tools):

| What you're running | Model tier |
|---|---|
| Single-platform skills (most daily SOC work) | Any capable small model — pick on **speed/VRAM** (e.g. Granite 4 Tiny, Gemma 4 E4B). All hit ~100%. |
| Multi-step **cross-platform** pivots | A stronger **orchestrator** — Qwen3 8B/4B or Gemma 4 12B held up best; GPT-OSS 20B is a great single-turn selector but less consistent multi-step. |
| Avoid | Single-turn function-calling *specialists that don't chain* (see the [Hammer case study](#case-study-hammer21-3b--best-at-tool-calling--can-drive-a-skill)). |

The two full matrices live in [`evals/SCORECARD.md`](../evals/SCORECARD.md) (single-turn
tool selection) and [`evals/AGENTIC.md`](../evals/AGENTIC.md) (multi-step skill orchestration).

---

## Why runtime & config choice matters

The repo's thesis is that small local models are now good enough to drive these tools reliably —
*if you serve them well*. Our measurements show the same model (identical 98% accuracy) swings
**2.4× in sequential latency and ~30× in concurrent throughput** purely on runtime + config.
Picking the runtime is a real deployment lever, and the eval harness exists to measure it on your
own hardware rather than guessing from a leaderboard.

## Runtime benchmark (three-way)

**Setup.** Same model held constant — **Qwen3-4B** (vLLM: `Qwen/Qwen3-4B` fp16, `--tool-call-parser
hermes`; Ollama: `qwen3:4b` Q4 GGUF; llama.cpp: `Qwen3-4B-Q4_K_M.gguf`, `--jinja --parallel -ngl
99`). Single 16 GB GPU, **one runtime at a time** (they can't coexist — see below). Workload: our
combined 28-tool eval + a concurrency harness. **Accuracy was identical (98% tool-selection) across
all three** — the runtime changes *how fast*, not *what the model picks*.

**Sequential** (one request at a time — how the evals and a single analyst actually run):

| Runtime | accuracy | mean/call | median | p90 | total (50 tasks) | VRAM |
|---|---|---|---|---|---|---|
| **llama.cpp** (Q4) | 98% | **4.21 s** | **3.00 s** | 7.57 s | **210.6 s** | ~5 GB |
| Ollama (Q4) | 98% | 9.97 s | 8.10 s | 21.39 s | 498.7 s | 5.1 GB |
| vLLM (fp16) | 98% | 10.74 s | 10.10 s | 15.97 s | 537.0 s | ~8 GB |

**Concurrency** (N requests fired in parallel — the production case, many simultaneous users):

| N | Ollama (total / req·s⁻¹) | llama.cpp | vLLM |
|---|---|---|---|
| 1 | 17.4 s / 0.06 | 3.0 s / 0.33 | 5.3 s / 0.19 |
| 4 | 69.1 s / 0.06 | 9.8 s / 0.41 | 5.8 s / 0.68 |
| 8 | 141.1 s / 0.06 | 14.7 s / 0.55 | 6.7 s / 1.20 |
| 16 | 281.9 s / 0.06 | 19.1 s / 0.84 | **8.5 s / 1.88** |

**What the data says:**

1. **The surprise: direct llama.cpp is ~2.4× faster than Ollama on sequential — even though Ollama
   *is* llama.cpp under the hood.** Same model, same Q4 quant, same engine, identical accuracy, yet
   median 3.0 s vs 8.1 s. That gap is Ollama's wrapper overhead (plus likely template-driven
   reasoning-length differences). Ollama's convenience carries a real, measurable latency tax.
2. **Concurrency: vLLM > llama.cpp ≫ Ollama.** Ollama's total time scales **linearly** with N — it
   serializes (default `OLLAMA_NUM_PARALLEL=1`). llama.cpp with `--parallel` **batches** (14× Ollama
   throughput at N=16, at a light Q4 footprint). vLLM's PagedAttention batches best (**31× Ollama,
   ~2.2× llama.cpp**) and keeps total time nearly flat as load climbs.
3. **Resource is a quant story, not a runtime tax.** Ollama/llama.cpp Q4 ≈ 5 GB; vLLM fp16 ≈ 8 GB
   weights + KV reservation. Serve an AWQ/GPTQ 4-bit model under vLLM and its weights drop to ~2.5 GB.
4. **One runtime per 16 GB GPU.** vLLM reserves `--gpu-memory-utilization` (≈ 9.6 GB at 0.6) up
   front; a co-resident Ollama then can't fit and spills to CPU (observed: 2.3 GB GPU / 4 GB CPU),
   which tanks it. Measure each runtime with the GPU to itself.

> **A config gotcha that will waste your time:** llama.cpp offloads **0 layers to GPU by default** —
> you *must* pass `-ngl 99` (or it runs on CPU: GPU util pinned at ~0 %, ~45 s/call). After `-ngl 99`,
> util spikes to ~99 % and calls drop to ~4 s. Confirm the startup log prints `offloaded N/N layers`.

## Model selection: tool *selection* ≠ skill *orchestration*

Two eval layers, because they measure different capabilities:

- **Single-turn** ([`SCORECARD.md`](../evals/SCORECARD.md)) — given a prompt, does the model pick the
  right tool and fill its args? Every capable small model scores ~100% per-server.
- **Multi-step** ([`AGENTIC.md`](../evals/AGENTIC.md)) — can the model *drive a whole `SKILL.md`
  procedure*: call the right sequence, feed results forward, synthesize a conclusion?

The gap between them is the whole point. Single-platform skills are solved by everyone; the **5-tool
cross-platform pivot separates the field** (some models cover all 5 tools, the smallest cover ~40 %).
A model that leads the single-turn scorecard can lag on multi-step orchestration — invisible unless
you measure the multi-step case.

### Case study: Hammer2.1-3b — "best at tool calling" ≠ "can drive a skill"

[Hammer2.1-3b](https://huggingface.co/MadeAgents/Hammer2.1-3b) is a 3B model that **tops the Berkeley
Function Calling Leaderboard for its size** — a tempting fast-default (1.9 GB, correct call on the
first shot). We ran it through both eval layers:

- **Formatting: flawless** — it emitted the exactly-correct tool + args every time.
- **Single-turn selection: below the field** — 73 % on the combined 28-tool registry (vs 92–100 %),
  weak on the identity tools. A 3B specialist is a weaker *selector* than the generalist models.
- **Multi-step: it fails** — it is a *single-turn* function caller. It makes one correct call, sees
  the result, signals "done", and stops. So it drives skills at only 20–50 % coverage and never
  reaches the goal. Since f0_sectools *is* multi-step skills, that's disqualifying — no matter how
  fast (it was the fastest we tested).

**The lesson:** BFCL measures "given a function, emit a correct call." Our workload is "select the
right tool across a security domain *and orchestrate a multi-step chain*." Those are different
capabilities. Pick a model on the eval that matches how it will actually be used — which is why the
agentic eval exists.

> **Runtime note for Hammer-class models:** Hammer's native output is a bare JSON array
> (`[{"name":..,"arguments":..}]`), which Ollama won't parse into OpenAI `tool_calls`. It works under
> **vLLM with `--tool-call-parser xlam`**. Another reminder that "tool-capable" and "works through
> *this runtime's* tool interface" are different things.

## Reproduce on your hardware

The numbers above are one box; re-run on yours. Single-turn accuracy + per-origin routing:

```bash
# combined 28-tool registry, per-origin breakdown, 3 runs
uv run python -m evals.run --server all --base-url <your-endpoint>/v1 --model <model> --runs 3
```

Full matrices (point `--base-url` at Ollama, vLLM, or llama-server — all OpenAI-compatible):

```bash
uv run python -m evals.scorecard --base-url <endpoint>/v1            # single-turn scorecard
uv run python -m evals.agentic_scorecard --base-url <endpoint>/v1    # multi-step + speed/VRAM
```

See [`evals/README.md`](../evals/README.md) for the model sweep + eviction notes, and
[`running-with-local-models.md`](running-with-local-models.md) for serving each runtime with
tool-calling enabled.

## Caveats

- **One box, one model.** Absolute latencies are from a 16 GB GPU running Qwen3-4B; treat them as
  illustrative. The *ordering* and the *patterns* are what generalize.
- **Config dominates.** Quant (Q4 vs fp16), `-ngl`, `--parallel` / `OLLAMA_NUM_PARALLEL`, and
  `--gpu-memory-utilization` move the numbers far more than the runtime name. Tune before concluding.
- **Power delivery is a hidden latency axis.** A laptop GPU on an underpowered adapter (or on battery)
  gets software-power-capped: clocks throttle hard while `HW Thermal Slowdown` stays off — we observed an
  SM clock pinned at ~9% of max with `SW Power Cap: Active`, roughly a 10× latency hit. This throttles
  *latency, not correctness*: deterministic decoding (temperature 0) emits identical tokens at any clock,
  so accuracy and VRAM are unaffected. Check `nvidia-smi -q -d PERFORMANCE` and measure speed only on the
  machine's full-power adapter.
- **The agentic numbers are mock-driven** (deterministic canned tool output), `runs`-averaged, and
  `goal-reached` is *directional* for the hard multi-step skill (high run-variance even at
  temperature 0) — read **coverage%** as the stable capability signal. See `AGENTIC.md`.
- **The llama.cpp-vs-Ollama sequential gap** is partly wrapper overhead and partly template/reasoning
  differences; both point to the same practical advice (go direct if you want llama.cpp's speed).
