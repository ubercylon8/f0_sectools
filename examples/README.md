# examples/

Runnable and readable artifacts backing the project's flagship claims — every
major claim in the [README](../README.md) has one here.

| Directory | Claim it demonstrates |
|---|---|
| [`findings/`](findings/README.md) | *"Every tool returns one normalized schema"* — a sample finding per server, schema-validated in CI |
| [`transcripts/`](transcripts/README.md) | *"A small model drives a full triage"* and *"a model can never write alone"* — annotated sessions, including both fail-closed paths of the write gate |
| [`personas/`](personas/README.md) | *"One evidence base, four altitudes"* — the same findings rendered by all five persona renderers, reproducible with real code |
| [`mcp/`](mcp/README.md) | Client wiring — MCP config snippets for Claude Desktop / Claude Code / generic stdio clients |

Fastest live demo (offline, no GPU, no tenant):
`uv run python scripts/demo_mock_findings.py` — see [docs/demo.md](../docs/demo.md).
