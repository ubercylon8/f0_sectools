## What & why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist (mirrors the Critical Rules in CLAUDE.md)

- [ ] **Read-only by default** — any state-changing action is routed through
      `core/gating/` and requires a config flag **and** a confirmation token, and
      is audited.
- [ ] **Returns the findings schema** — no ad-hoc text output.
- [ ] **Redaction at the boundary** — output is redacted, including error paths.
- [ ] **Safety logic stays in `core/`** — no re-implemented redaction/auth/schema/gating in a server.
- [ ] **Small-model-safe** — flat args, short closed enums, ≤ ~8 tools/server, bounded output.
- [ ] **Eval task added** for any new tool (`evals/<platform>/tasks.yaml`).
- [ ] **No secrets staged** — no `.env` (only `.env.*.example`).
- [ ] `uv run pytest` and `uv run ruff check .` pass.
