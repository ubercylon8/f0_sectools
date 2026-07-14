# pi integration

Files for running f0_sectools under [pi](https://pi.dev/docs/latest):

| File | Purpose |
|------|---------|
| `mcp.json` | [`pi-mcp-extension`](https://pi.dev/packages/pi-mcp-extension) config wiring the six MCP servers (stdio via `uv run --directory`). Copy to `~/.pi/agent/mcp.json` or `.pi/mcp.json`. |
| `AGENTS.md` | Base agent identity — read-only / never-fabricate principles (the `SOUL.md` equivalent). Copy to `~/.pi/agent/AGENTS.md`. |
| `prompts/*.md` | The four persona lenses as prompt templates → `/ciso`, `/threat-hunter`, `/detection-engineer`, `/security-engineer`. Point `settings.prompts` at this dir. |

pi has no native MCP — the `mcp.json` is consumed by the `pi-mcp-extension`
bridge, not by pi directly.

**Full setup and usage:** see the canonical guide at
[`docs/user-guide/runtimes/pi.md`](../../docs/user-guide/runtimes/pi.md).
(Single source of truth — don't duplicate setup steps here.)
