# Server README template

Copy this structure for every new server README (`servers/<platform>-mcp/README.md`).
The best current examples: [`defender-mcp`](defender-mcp/README.md) and
[`projectachilles-actions-mcp`](projectachilles-actions-mcp/README.md).
Sections marked *(if any)* are omitted when empty — everything else is required
before a server can be marked live-validated.

```markdown
# f0-<platform>-mcp

One-paragraph summary: what platform, which API, read-only or read+gated,
built on `f0-sectools-core`.

## Read tools

| Tool | API endpoint | Permission/scope |
|------|--------------|------------------|
(one row per tool; link the generated page for full parameter details:
docs/reference/tools/<platform>.md)

Note the permission-aware behaviour: missing permission → posture finding
naming the grant, never a crash.

## Gated write actions   *(if any)*

Table as above, then the four-step gate summary (flag → intent → confirmation
→ audit) with the platform's exact flag name. Link
docs/user-guide/gated-actions.md rather than re-explaining the machinery.

## Configuration

Point at `.env.<platform>.example`; name every required variable and the
exact permissions/scopes/licenses, including admin-consent notes.

## Run

    uv run f0-<platform>-mcp   # stdio MCP server

## Live validation   *(status + quirks)*

State whether the server is live-validated, the smoke command
(`uv run python scripts/live_smoke_<platform>.py`), and any platform quirks
the live run surfaced (field-name mismatches, throttling behaviour, license
gates) — these save the next operator hours.
```

Checklist when finishing a server (mirrors CONTRIBUTING's recipe):

- [ ] Every registered tool appears in a table row
- [ ] Every required env var and permission is named, with license caveats
- [ ] Gated actions link the operator guide instead of duplicating it
- [ ] Smoke-test command included; live-validation status stated honestly
- [ ] `uv run python scripts/gen_docs.py` re-run so the generated reference
      picks up the tools
