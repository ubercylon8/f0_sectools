# Hermes Agent integration

Files for running f0_sectools under [Hermes Agent](https://hermes-agent.nousresearch.com/docs/):

| File | Purpose |
|------|---------|
| `config.example.yaml` | Manual-merge alternative to the distribution — copy its `mcp_servers`, `skills`, and `personalities` blocks into an existing Hermes profile's `config.yaml`. |
| `distribution/distribution.yaml` | Distribution manifest for git-based install into Hermes. Specifies environment requirements (`F0_SECTOOLS_DIR`, Hermes version). |
| `distribution/SOUL.md` | Base agent identity — read-only / never-fabricate operating principles. Auto-installed to `~/.hermes/profiles/f0sectools/SOUL.md` by distribution installer; or manually copy to `~/.hermes/SOUL.md` for manual-merge setup. |
| `distribution/config.yaml` | The seven f0_sectools MCP servers (defender, entra, limacharlie, projectachilles, pa-actions, intune, tenable) under `mcp_servers`, plus personas and skills — auto-installed to `~/.hermes/profiles/f0sectools/config.yaml`. Hermes reads MCP servers from `config.yaml`, not a separate `mcp.json`. |

**Full setup and usage:** see the canonical guide at
[`docs/user-guide/runtimes/hermes.md`](../../docs/user-guide/runtimes/hermes.md).
(Single source of truth — don't duplicate setup steps here.)
