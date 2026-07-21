# Running f0_sectools on opencode

[opencode](https://opencode.ai) (≥ 1.18) is a terminal AI agent with **native
MCP** and **native SKILL.md skills** (progressive disclosure). f0_sectools ships
its opencode wiring **inside the repo** — run opencode from the checkout and
everything is already connected. Validated on opencode 1.18.4 with a local
Qwen3.5-9B (llama.cpp).

## Quickstart

1. Do [getting started](../getting-started.md) once (checkout, `uv sync
   --all-packages`, per-platform `.env.<platform>` files at the repo root).
2. Configure a model/provider in your **global** opencode config if you haven't
   already (e.g. a llama.cpp or Ollama OpenAI-compatible endpoint — see
   [running with local models](../../running-with-local-models.md)). The
   project config never touches your model setup.
3. From the checkout root:

   ```bash
   cd ~/path/to/sec-tools
   opencode
   ```

That's it. The project config auto-loads:

- **7 MCP servers** from [`opencode.json`](../../../opencode.json) (relative
  `uv run` commands — verify with `opencode mcp list`: six read servers
  `connected`, `f0-pa-actions` `disabled`).
- **22 skills** from `.opencode/skills/` (symlinks into the portable
  [`skills/`](../../../skills/) set — the agent loads the matching playbook
  on demand via its `skill` tool).
- **4 personas** from `.opencode/agents/` — switch agents in the TUI (Tab or
  the agent selector): `ciso`, `threat-hunter`, `detection-engineer`,
  `security-engineer`.

## One-shot (non-interactive) use

```bash
opencode run --agent security-engineer \
  "Which LimaCharlie sensors are dormant sleepers? Summarize."
```

Add `-m <provider>/<model>` to pick a specific local model for the run.

## Security notes

- **Gated writes ship disabled.** `f0-pa-actions` (the ProjectAchilles actions
  server) is `"enabled": false` in `opencode.json`. Under opencode the model
  has **shell access**, so the gated-write confirmation flow is **not
  forge-resistant** — a misbehaving model could in principle drive
  `scripts/confirm_action.py` itself. Enable the server only if you accept
  that risk; otherwise keep it disabled **and** keep
  `PROJECTACHILLES_ALLOW_WRITE=false` in `.env.projectachilles` (defense in
  depth — same caveat as the [Hermes runtime](hermes.md)).
- Everything else is read-only by design; credentials stay in the gitignored
  `.env.<platform>` files and never enter model context.

## Troubleshooting

- **`opencode mcp list` shows a server failed** — run the server directly
  (`uv run --directory . f0-defender-mcp`) to see the startup error; usually a
  missing `.env.<platform>` (servers resolve them from the repo root).
- **Skills missing from `opencode debug skill`** — that CLI snapshot races the
  skill scan and shows a partial list (observed on 1.18.4); a real session
  sees all skills. Trust an in-session check ("list your available skills"),
  not the debug command.
- **Skills missing on Windows** — the `.opencode/skills/` entries are POSIX
  symlinks; enable `git config core.symlinks true` + Windows Developer Mode
  before cloning.
- **Config edits don't apply** — opencode loads config at startup; restart it
  after changing `opencode.json`, agents, or skills.

## Layout (for maintainers)

See [`integrations/opencode/README.md`](../../../integrations/opencode/README.md).
Drift guards in `integrations/test_integrations_valid.py` keep the server set,
the disabled-write default, and the skill symlink farm in sync with the repo.
