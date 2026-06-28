# Contributing to f0_sectools

Thanks for your interest in contributing! f0_sectools is part of the F0RT1KA /
ProjectAchilles ecosystem. Please read this guide and [CLAUDE.md](CLAUDE.md) —
the latter contains the architectural rules every contribution must follow.

## Ground rules (non-negotiable)

These mirror the Critical Rules in [CLAUDE.md](CLAUDE.md):

1. **Read-only by default.** New platform tools are read-only. State-changing
   actions are gated behind a config flag **and** a human confirmation token,
   routed through `core/gating/`, and audited.
2. **Secrets never leave the host or reach the model.** Use per-platform `.env`
   files (gitignored). Never log, return, or prompt-inject credentials.
3. **Return the findings schema.** Every tool emits the normalized schema from
   `core/schema/`. No ad-hoc text output.
4. **Safety logic lives in `core/`.** Do not re-implement redaction, auth,
   schema, or gating inside a server.
5. **Design tools for small models.** Flat args, short closed enums, few tools
   per server, bounded/paginated output. See the "Designing Tools for Small
   Models" section in CLAUDE.md.

## Adding a platform server

1. Create `servers/<platform>-mcp/` and import `core/`.
2. Define read tools first (target ≤ ~8 flat tools per server).
3. Add `.env.<platform>.example` documenting required credentials (no secrets).
4. Write **contract tests** against mocked platform APIs (schema shape,
   redaction, pagination, gating refusal without flag/token).
5. Add at least one **eval task set** in `evals/` so the tools' callability by a
   local model is measured.

## Development workflow

- **Language:** Python 3.11+. Tooling: `uv`, `pytest`, `ruff`.
- **Commits:** Conventional Commits (e.g. `feat(wazuh): add alert query tool`).
- **Tests must pass** (`pytest`) and code must lint (`ruff check`) before a PR.
- Stage specific files; never `git add -A` (avoid committing `.env*` or local
  data).

## Testing bar

- **Contract tests** are mandatory for every tool (mocked APIs, deterministic).
- The **small-model tool-calling eval** is built alongside the first server and
  expected for new tools. If a tool passes contract tests but a small model
  cannot reliably call it, the tool's design is wrong — simplify the schema.

## License

By contributing, you agree your contributions are licensed under the Apache
License 2.0, consistent with the rest of the project.
