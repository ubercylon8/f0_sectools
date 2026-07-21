# Hermes Agent integration

Files for running f0_sectools under [Hermes Agent](https://hermes-agent.nousresearch.com/docs/):

| File | Purpose |
|------|---------|
| `distribution/distribution.yaml` | Distribution manifest for git-based install into Hermes. Specifies environment requirements (`F0_SECTOOLS_DIR`, Hermes version). |
| `distribution/mcp.json` | MCP server sources — the seven f0_sectools servers (defender, entra, limacharlie, projectachilles, pa-actions, intune, tenable) and their launch commands. |
| `distribution/SOUL.md` | Base agent identity — read-only / never-fabricate operating principles. Copy to `~/.hermes/SOUL.md`. |
| `config.yaml` | Personas, skills, and tool-scoping — automatically installed to `~/.hermes/profiles/f0sectools/config.yaml`. |

**Full setup and usage:** see the canonical guide at
[`docs/user-guide/runtimes/hermes.md`](../../docs/user-guide/runtimes/hermes.md).
(Single source of truth — don't duplicate setup steps here.)
