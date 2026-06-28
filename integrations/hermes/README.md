# Hermes Agent integration

Files for running f0_sectools under [Hermes Agent](https://hermes-agent.nousresearch.com/docs/):

| File | Purpose |
|------|---------|
| `SOUL.md` | Base agent identity — read-only / never-fabricate operating principles. Copy to `~/.hermes/SOUL.md`. |
| `config.example.yaml` | Merge into `~/.hermes/config.yaml`: wires the MCP servers, points `skills.external_dirs` at this repo's `skills/`, and defines the four role personalities. |

**Full setup and usage:** see the canonical guide at
[`docs/user-guide/runtimes/hermes.md`](../../docs/user-guide/runtimes/hermes.md).
(Single source of truth — don't duplicate setup steps here.)
