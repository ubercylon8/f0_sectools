# opencode runtime wiring

[opencode](https://opencode.ai) (≥ 1.18) is wired as an **in-repo project
config** — unlike the other runtimes, the actual wiring does **not** live in
this directory:

| What | Where | Why |
|---|---|---|
| MCP servers (7) | [`/opencode.json`](../../opencode.json) | opencode auto-loads the project config when run inside the checkout; commands are relative (`uv run --directory .`), so nothing needs rendering per user |
| Skills (22) | [`/.opencode/skills/`](../../.opencode/skills/) | committed relative symlinks into [`skills/`](../../skills/) — opencode's **native** SKILL.md loader (progressive disclosure) picks up the one portable skill set, no forks |
| Personas (4) | [`/.opencode/agents/`](../../.opencode/agents/) | project agent files (CISO, threat hunter, detection engineer, security engineer) — switch with the TUI agent selector |

**Quickstart:** `cd` into the checkout (with `.env.<platform>` files in place —
see [getting started](../../docs/user-guide/getting-started.md)) and run
`opencode`. Full guide: [user-guide/runtimes/opencode.md](../../docs/user-guide/runtimes/opencode.md).

**Security:** the gated-write server `f0-pa-actions` ships **`"enabled":
false`**. Under opencode the model has shell access, so the gated-write
confirmation is **not forge-resistant** (a misbehaving model could drive
`confirm_action.py` itself). Enable it only if you accept that risk, and keep
`PROJECTACHILLES_ALLOW_WRITE=false` otherwise — same caveat as the Hermes
runtime. As runtime defense-in-depth, the project config pre-arms opencode's
`"ask"` permission on all four write tools — each write call requires an
interactive TUI approval the model cannot forge (auto-rejected in
non-interactive runs; verified live). The enable procedure and approval flow
are documented in
[user-guide/runtimes/opencode.md](../../docs/user-guide/runtimes/opencode.md#enabling-gated-writes-projectachilles-actions).

**Windows note:** the skill entries are POSIX symlinks; on Windows enable
`git config core.symlinks true` + Developer Mode before cloning, or the skills
won't resolve.

Drift guards for all three pieces live in
[`integrations/test_integrations_valid.py`](../test_integrations_valid.py).
