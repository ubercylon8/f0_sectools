# Running f0_sectools with local models

f0_sectools is designed so a **small, local model** drives the security tools with
**no data leaving your host**. This page shows how the pieces fit and how to wire
the nine f0_sectools MCP servers to a locally-served model.

## Architecture

```
                                  MCP (stdio): tool calls / results, all redacted
┌───────────────────────────┐   ┌──────────────────────────────────┐
│ MCP-capable agent /       │   │ Microsoft-platform servers       │
│ orchestrator              │   │ defender · entra · intune ·      │
│                           │   │ purview · sentinel               │
│ OpenAI-compatible HTTP    │   │ (2 gated-write tools)            │
│ (/v1/chat/completions)    │   ├──────────────────────────────────┤
└───────────────────────────┘   │ Other-platform servers           │
                                │ limacharlie · tenable ·          │
                                │ projectachilles (+actions)       │
                                │ (4 gated-write tools)            │
                                └──────────────────────────────────┘
              │
              ▼  OpenAI-compatible tool-call requests
┌───────────────────────────┐
│ Local model server        │
│ vLLM  or  llama.cpp       │
└───────────────────────────┘
```

Grouped by credential family, not drawn as nine literal boxes: the
**Microsoft-platform group** (defender, entra, intune, purview, sentinel) each
authenticate to your tenant via an Entra app registration (its own
`.env.<platform>` — client ID/secret and tenant ID are not shared across
servers, even within the group); the **other-platform group** (limacharlie,
tenable, projectachilles + its `pa-actions` write server) each hold their own
vendor API credential. Every server is still an independent process with its
own `.env.<platform>` — the grouping is only to keep the diagram readable.

Two distinct components:

1. **The local model server** — vLLM or llama.cpp, exposing an OpenAI-compatible
   `/v1/chat/completions` endpoint. This runs the model (GPT-OSS, Gemma 4, Qwen3).
2. **An MCP-capable agent/orchestrator** — the loop that sends the user's request +
   the MCP tool schemas to the model, executes the tool calls the model returns
   against the f0_sectools MCP servers, and feeds results back. vLLM/llama.cpp do
   **not** speak MCP themselves; the orchestrator bridges model ↔ MCP. Nothing
   requires connecting all nine servers at once — point the orchestrator at
   whichever subset covers the platforms you actually run; each server is
   independent (its own `.env.<platform>`, its own process).

Nothing in this path calls out to a third party: the model is local, the MCP
servers talk only to the security platforms you configured, and credentials never
leave the host.

Two servers carry gated write actions — Defender (`isolate_host`,
`release_host`) and ProjectAchilles's `pa-actions` server (`run_test`,
`schedule_test`, `set_schedule_status`, `cancel_tasks`) — every other server,
and every other tool on those two, is read-only. See the
[security model](explanation/security-model.md) for how the confirmation gate
works.

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

Each server loads only its own `.env.<platform>` — copy the template for
whichever platforms you actually run; you do not need all nine to get started:

```bash
cp servers/defender-mcp/.env.defender.example           .env.defender     # fill in values
cp servers/entra-mcp/.env.entra.example                 .env.entra        # fill in values
cp servers/intune-mcp/.env.intune.example                .env.intune       # fill in values
cp servers/purview-mcp/.env.purview.example              .env.purview      # fill in values
cp servers/sentinel-mcp/.env.sentinel.example             .env.sentinel     # fill in values
cp servers/limacharlie-mcp/.env.limacharlie.example       .env.limacharlie  # fill in values
cp servers/tenable-mcp/.env.tenable.example               .env.tenable      # fill in values
cp servers/projectachilles-mcp/.env.projectachilles.example .env.projectachilles  # fill in values
```

All `.env.*` files are gitignored. The servers load them at startup; the
gated-write `pa-actions` server shares `.env.projectachilles` with the
read-only `projectachilles-mcp` server and additionally needs
`PROJECTACHILLES_ALLOW_WRITE=true` before any write tool is usable.

## 3. Point an MCP client at the servers

Use [`examples/mcp/mcp.json`](../examples/mcp/mcp.json) — replace the absolute path
with your checkout. It launches each server via `uv run --directory <repo>` so the
server finds its `.env.<platform>` file. Any MCP-capable client that reads the
standard `mcpServers` format works (Claude Code, and most agent frameworks).
Delete the entries for platforms you don't run — an MCP server with no
credentials configured will fail to start.

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

For **which runtime and which model to choose** (Ollama vs vLLM vs llama.cpp
benchmarks, single-turn vs multi-step model selection, and deployment guidance),
see [`runtime-performance.md`](runtime-performance.md).
