# Getting started

Do this once. Every runtime builds on these steps.

## Prerequisites

- **Python 3.11+** and **[uv](https://docs.astral.sh/uv/)** (`which uv` — note
  the path; some runtimes need it absolute).
- A **local model server** exposing an OpenAI-compatible endpoint (vLLM or
  llama.cpp), or a runtime that bundles one (LM Studio). Use a **tool-calling**
  model — Qwen3, GPT-OSS, or Gemma 4.
- API credentials for the platform(s) you want to connect (see below).

## 1. Get the code and install

```bash
git clone https://github.com/ubercylon8/f0_sectools.git
cd f0_sectools
uv sync --all-packages          # installs core + every server (editable)
```

## 2. Configure credentials (never committed)

Each server reads its own `.env.<platform>` from the repo root. These are
gitignored — they never enter version control, logs, the model, or any config
file.

```bash
cp servers/defender-mcp/.env.defender.example .env.defender   # fill in values
cp servers/entra-mcp/.env.entra.example       .env.entra      # fill in values
```

The `.env.*.example` files document the exact Microsoft Graph **application
permissions** each server needs (read-only, admin consent). A missing permission
or license doesn't crash anything — the tool returns a `posture` finding telling
you what to grant.

## 3. Verify against your tenant

The smoke scripts call every tool once and print **redacted** findings:

```bash
uv run python scripts/live_smoke_defender.py
uv run python scripts/live_smoke_entra.py
```

You should see real data (or graceful "permission not granted / rate limited"
findings). Secrets are never printed.

## 4. Pick a runtime

Continue with your chosen agent platform:

- [Hermes Agent](runtimes/hermes.md) (recommended)
- [LM Studio](runtimes/lm-studio.md)
- [Open WebUI](runtimes/open-webui.md)
- [Claude Code](runtimes/claude-code.md)

## Optional: measure your model's tool-calling reliability

Before trusting a given model to drive the tools, score it:

```bash
uv run python -m evals.run --server defender \
  --base-url http://localhost:8000/v1 --model <model-id> --runs 3
```

A low score means the tool's schema is too hard for that model — pick a stronger
model or simplify the tool. See [`evals/`](../../evals/).
