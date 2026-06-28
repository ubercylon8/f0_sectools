# Runtime: Claude Code

[Claude Code](https://code.claude.com) is a terminal agent with native MCP and
the same **agentskills.io** skill format f0_sectools uses — so our skills work
unmodified. (Note: Claude Code runs Anthropic's hosted models, not a local
model. Use it for development and for driving the tools where local-only privacy
isn't required; for fully-local operation use Hermes or LM Studio.)

Prerequisite: finish [getting started](../getting-started.md).

## Add the MCP servers

From the repo root:

```bash
claude mcp add f0-defender -- uv run --directory "$(pwd)" f0-defender-mcp
claude mcp add f0-entra    -- uv run --directory "$(pwd)" f0-entra-mcp
```

Or add a project-scoped `.mcp.json` (same `mcpServers` format as
[`examples/mcp/mcp.json`](../../../examples/mcp/mcp.json)).

Tools appear as `mcp__f0-defender__list_incidents`, etc.

## Use the skills

Claude Code discovers skills from `.claude/skills/` (project) or
`~/.claude/skills/`. Make our skills available, e.g. symlink them:

```bash
mkdir -p .claude/skills
ln -s "$(pwd)/skills/defender/triage-incident"  .claude/skills/triage-defender-incident
ln -s "$(pwd)/skills/defender/posture-summary"  .claude/skills/defender-posture-summary
ln -s "$(pwd)/skills/defender/threat-hunt"      .claude/skills/defender-threat-hunt
```

Then ask naturally ("triage our active incidents", "posture summary") and the
matching skill activates.

## Personas

Claude Code has no `/personality` switch. For a role lens, paste the relevant
mode from [`prompts/f0-sectools-system-prompt.md`](../../../prompts/f0-sectools-system-prompt.md)
into your request, or add it to a project `CLAUDE.md`.

## Notes

- Everything is read-only; no gated write actions are exposed yet.
- Skills are the **same files** used by Hermes — no Claude-specific copies.
