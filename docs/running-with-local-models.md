# Running f0_sectools with local models

f0_sectools is designed so a **small, local model** drives the security tools with
**no data leaving your host**. This page shows how the pieces fit and how to wire
the Defender and Entra MCP servers to a locally-served model.

## Architecture

```
┌─────────────────────────┐     MCP (stdio)      ┌──────────────────────┐
│  MCP-capable agent /     │ ───────────────────▶ │  f0-defender-mcp     │ ─┐
│  orchestrator            │                      │  f0-entra-mcp        │  │  Microsoft
│                          │ ◀─────────────────── │  (read-only tools)   │  │  Graph
│   ▲   tool calls / results                      └──────────────────────┘  │  (your tenant)
│   │                      │                                                 │
│   ▼  OpenAI-compatible   │                                                 ▼
│  HTTP (/v1/chat/...)     │                                          findings (redacted)
└──────────┬──────────────┘
           │
           ▼
┌──────────────────────────┐
│  Local model server      │   GPT-OSS / Gemma 4 / Qwen3
│  vLLM  or  llama.cpp      │   served on YOUR hardware
└──────────────────────────┘
```

Two distinct components:

1. **The local model server** — vLLM or llama.cpp, exposing an OpenAI-compatible
   `/v1/chat/completions` endpoint. This runs the model (GPT-OSS, Gemma 4, Qwen3).
2. **An MCP-capable agent/orchestrator** — the loop that sends the user's request +
   the MCP tool schemas to the model, executes the tool calls the model returns
   against the f0_sectools MCP servers, and feeds results back. vLLM/llama.cpp do
   **not** speak MCP themselves; the orchestrator bridges model ↔ MCP.

Nothing in this path calls out to a third party: the model is local, the MCP
servers talk only to the security platforms you configured, and credentials never
leave the host.

## 1. Serve a model locally (example: vLLM)

```bash
# GPT-OSS-20b with tool-calling enabled, OpenAI-compatible on :8000
vllm serve openai/gpt-oss-20b --enable-auto-tool-choice --tool-call-parser hermes
# -> http://localhost:8000/v1   (no API key needed locally)
```

llama.cpp equivalent:

```bash
llama-server -m gpt-oss-20b.gguf --jinja --port 8000
# -> http://localhost:8000/v1
```

## 2. Configure credentials (never committed)

```bash
cp servers/defender-mcp/.env.defender.example .env.defender   # fill in values
cp servers/entra-mcp/.env.entra.example       .env.entra      # fill in values
```

Both files are gitignored. The servers load them at startup.

## 3. Point an MCP client at the servers

Use [`examples/mcp/mcp.json`](../examples/mcp/mcp.json) — replace the absolute path
with your checkout. It launches each server via `uv run --directory <repo>` so the
server finds its `.env.<platform>` file. Any MCP-capable client that reads the
standard `mcpServers` format works (Claude Code, and most agent frameworks).

```bash
# sanity-check a server starts and lists its tools:
uv run f0-defender-mcp   # stdio server; Ctrl-C to stop
```

## 4. Validate model ↔ tool reliability (recommended)

Before trusting a given local model to drive these tools, measure its
tool-calling reliability with the eval harness:

```bash
uv run python -m evals.run --server defender \
  --base-url http://localhost:8000/v1 --model openai/gpt-oss-20b --runs 3
```

See [`evals/README.md`](../evals/README.md). A model that scores poorly on a tool
means the tool's schema is too hard for it — simplify, don't lower the bar.
