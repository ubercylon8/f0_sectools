# evals/

The **small-model tool-calling evaluation harness**. It points a real local
model (GPT-OSS, Gemma 4, Qwen3 — served via vLLM or llama.cpp's
OpenAI-compatible endpoint) at a server's tools and measures **callability**:

- **Tool-selection accuracy** — given a natural-language task, is the right tool chosen?
- **Argument-filling success rate** — are arguments populated correctly across N runs?
- **Degradation signals** — tools that score poorly (too many tools, oversized
  enums, nested args) are flagged as **design defects to fix**, reported as
  success rates rather than pass/fail.

Task sets live here as YAML. Run outputs are written to `results/` (gitignored).
A tool that passes contract tests but fails here has a design problem — simplify
the schema, do not lower the bar.

## Scorecard & multi-server eval

To score a single server against a single model, use `evals/run.py` directly
(pass `--server all` to run the combined 22-tool registry — every server's
tools registered at once — which is the ad-hoc composition test: does a model
still pick the right tool when many platforms' tools are all on the table
together):

```bash
uv run python -m evals.run --server all \
  --base-url http://localhost:8000/v1 --model <model-id> --runs 3
```

To sweep **every model in `models.yaml` against every server** (plus `all`) and
produce a model x server matrix, use `evals/scorecard.py`:

```bash
uv run python -m evals.scorecard --base-url http://localhost:11434/v1 --runs 1
# narrow the sweep:
uv run python -m evals.scorecard --base-url ... --models gpt-oss:20b-c128k --servers defender,all
# re-run cells already recorded instead of skipping them:
uv run python -m evals.scorecard --base-url ... --force
# compute and print without persisting anything:
uv run python -m evals.scorecard --base-url ... --no-write
```

Each (model, server) cell is written incrementally to `evals/results/<date>.json`
(gitignored, resumable — an interrupted sweep picks up where it left off and
already-recorded cells are skipped unless `--force`), and the run regenerates
[`SCORECARD.md`](SCORECARD.md), the checked-in markdown table of the latest
sweep.
