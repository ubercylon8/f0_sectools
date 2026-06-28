# Runtime: LM Studio

[LM Studio](https://lmstudio.ai) (≥ **0.3.17**) is the turnkey option: it loads
your local model, acts as an MCP client, and provides the chat UI — all in one
desktop app. It speaks **stdio** MCP, so our servers plug in with no proxy.

Prerequisite: finish [getting started](../getting-started.md).

## Setup

1. **Load a tool-calling model** in LM Studio (Qwen3, GPT-OSS, or Gemma 4).
   Confirm the model card lists tool use.

2. **Add the servers** — edit `~/.lmstudio/mcp.json` (in-app: right sidebar →
   **Program → Install → Edit mcp.json**). Use the absolute `uv` path (LM
   Studio's process won't have it on `PATH`):

   ```json
   {
     "mcpServers": {
       "f0-defender": {
         "command": "/home/jimx/.local/bin/uv",
         "args": ["run", "--directory", "/home/jimx/F0RT1KA/sec-tools", "f0-defender-mcp"]
       },
       "f0-entra": {
         "command": "/home/jimx/.local/bin/uv",
         "args": ["run", "--directory", "/home/jimx/F0RT1KA/sec-tools", "f0-entra-mcp"]
       }
     }
   }
   ```

   Save — LM Studio auto-reloads and starts the servers. (A copy lives at
   [`examples/mcp/mcp.json`](../../../examples/mcp/mcp.json).)

3. **Skills/personas** — LM Studio has **no skill system**. Paste
   [`prompts/f0-sectools-system-prompt.md`](../../../prompts/f0-sectools-system-prompt.md)
   as the **system prompt**. It carries the same operating principles and is
   **persona-switchable** ("switch to CISO mode", "as a threat hunter…").

## Use it

By default LM Studio **asks you to confirm each tool call** — which fits the
read-only, human-in-the-loop posture. Try:

- "What's our Microsoft Secure Score?"  → `get_secure_score`
- "List the high-severity Defender incidents." → `list_incidents`
- "As a CISO, give me a posture summary." → secure score + incidents, exec-framed

## Notes

- LM Studio also exposes an OpenAI-compatible server (Developer tab, default
  `http://localhost:1234/v1`) — point the [eval harness](../getting-started.md#optional-measure-your-models-tool-calling-reliability)
  at it to score the loaded model.
- First tool call may be slightly slow while `uv` resolves; subsequent calls are
  fast.
