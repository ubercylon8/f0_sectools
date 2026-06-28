# Runtime: Open WebUI

[Open WebUI](https://openwebui.com) (≥ **0.6.31**) supports MCP, but only over
**HTTP/SSE**. Our servers are **stdio**, so you bridge them with the **`mcpo`**
proxy (MCP-to-OpenAPI).

Prerequisite: finish [getting started](../getting-started.md).

## Setup

1. **Bridge each stdio server to HTTP with `mcpo`** (one port per server):

   ```bash
   # Defender on :8000
   uvx mcpo --port 8000 -- uv run --directory /home/jimx/F0RT1KA/sec-tools f0-defender-mcp
   # Entra on :8001 (separate terminal)
   uvx mcpo --port 8001 -- uv run --directory /home/jimx/F0RT1KA/sec-tools f0-entra-mcp
   ```

   `mcpo` exposes the tools as an OpenAPI endpoint Open WebUI can call.

2. **Register the tool servers** in Open WebUI → **Settings → Tools** (or
   **Admin → Tools**), adding `http://localhost:8000` and `http://localhost:8001`.

3. **Load a tool-calling model** (Ollama/llama.cpp/vLLM via Open WebUI). Confirm
   tool calling is enabled for it.

4. **Skills/personas** — Open WebUI has **no skill system**. Put
   [`prompts/f0-sectools-system-prompt.md`](../../../prompts/f0-sectools-system-prompt.md)
   in the model's **system prompt** (or set `TOOLS_FUNCTION_CALLING_PROMPT`).
   It's persona-switchable.

## Use it

Ask the same questions as any runtime — "list high-severity incidents", "as a
CISO, summarize posture". Open WebUI shows the tool calls and results inline.

## Notes

- Small models can struggle with multi-step tool use in Open WebUI; the system
  prompt's "one tool at a time" discipline matters here. Prefer a stronger
  tool-calling model.
- Keep the `mcpo` processes running while you use the tools; script them or run
  under a process manager for convenience.
