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
  that risk (see below); otherwise keep it disabled **and** keep
  `PROJECTACHILLES_ALLOW_WRITE=false` in `.env.projectachilles` (defense in
  depth — same caveat as the [Hermes runtime](hermes.md)).
- Everything else is read-only by design; credentials stay in the gitignored
  `.env.<platform>` files and never enter model context.

## Enabling gated writes (ProjectAchilles actions)

For **supervised, interactive** sessions only — never unattended. Three layers
stack; all of them stay in force:

1. **Enable the server** — in your checkout, edit `opencode.json`:
   `"f0-pa-actions": { …, "enabled": true }`, then restart opencode. (This
   dirties the working tree deliberately — revert with
   `git checkout -- opencode.json` when done.)
2. **Enable the write flag** — in `.env.projectachilles`:
   `PROJECTACHILLES_ALLOW_WRITE=true`, plus your confirmation mode
   (`PROJECTACHILLES_CONFIRM_MODE=chat` for in-chat "approved", or leave the
   default token/watcher — see [gated write actions](../../../CLAUDE.md#gated-write-actions)).
3. **opencode's own approval gate (ships pre-armed).** The project config
   marks all four write tools (`run_test`, `schedule_test`,
   `set_schedule_status`, `cancel_tasks`) as `"ask"`: every write **call**
   pops an approval prompt in the TUI that the model cannot answer or forge.
   Choose **`once`** each time — **never `always`**, which would waive the
   prompt for the rest of the session. Reads (`list_schedules`,
   `get_task_status`, `list_tasks`) stay friction-free. In non-interactive
   `opencode run`, write calls **auto-reject** (verified live) unless you pass
   `--auto` — don't pass `--auto` with writes enabled.

A typical gated run then looks like: you ask for a test → the write tool call
prompts (`once`) → the tool returns an **intent** finding → you confirm per
your gate mode (e.g. reply "approved" in chat) → the re-call prompts again
(`once`) → executes and is audited.

**Honest caveat:** the `ask` layer guards the *tool call* path, not the shell —
a misaligned model with bash access could still attempt to self-approve
outside the tools. The layering raises the bar; it is not forge-resistance.
Supervised sessions only.

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
