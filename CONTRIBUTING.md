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

## Adding a platform server — the recipe

The eight built servers follow an **identical pattern**; `core/` does not
change. Do it in this order, TDD-ing each code step. (Background:
[architecture](docs/explanation/architecture.md#the-server-pattern).)

1. **Config** — add `<Platform>Config` (dataclass + `from_env(prefix=...)`,
   required vars, optional `verify_tls`/`allow_write`, secrets never logged)
   to `core/auth/config.py`, with a test in `core/tests/test_config.py`.
2. **Scaffold** `servers/<platform>-mcp/`: `pyproject.toml` (deps
   `f0-sectools-core`, `mcp`, + the platform's client lib), `README.md`
   (follow [`servers/_TEMPLATE.md`](servers/_TEMPLATE.md)),
   `.env.<platform>.example` (document the exact required
   permissions/scopes), `f0_<platform>_mcp/__init__.py`, `tests/`. Then
   `uv sync --all-packages`.
3. **Client** (`client.py`) — thin wrapper exposing only the read methods
   needed. Async `httpx` for REST (static Bearer or OAuth); for a
   **synchronous vendor SDK**, wrap it and run tools via `asyncio.to_thread`.
4. **Errors** (`errors.py`) — `map_<platform>_error(...)`: auth → posture
   finding, `403` → `Finding.permission_missing`, `429` →
   `Finding.rate_limited`, gateway `502/503/504` → "API unavailable".
   **Every failure becomes a finding, never an exception.**
5. **Tools** (`tools.py`) — ≤ ~8 flat read tools returning `list[Finding]`;
   write the contract tests first (fake client) — live data validates real
   field names later.
6. **Server** (`server.py`) — `FastMCP`, one `@mcp.tool()` per tool, build the
   client from config, **redact at the boundary** (`redact_obj(f.model_dump())`).
7. **Evals** — `evals/<platform>/tasks.yaml` (≥1 task per tool) + add the
   server to `SERVERS` in `evals/test_eval_coverage.py` and `SERVER_MODULES`
   in `evals/run.py`.
8. **Smoke script** — `scripts/live_smoke_<platform>.py`.
9. **Live-test** — create `.env.<platform>` at the repo root (gitignored), run
   the smoke script, and fix-forward field-name/shape mismatches (this step
   always finds 1–3 — mocks encode assumptions; the live API is truth). Mark
   live-validated once clean.
10. **Skills** — three `SKILL.md` under `skills/<platform>/` (a
    posture/coverage skill, a gap/investigation skill, a platform-native
    one). Pick a default focus and say so.
11. **Docs & wiring** — regenerate the reference
    (`uv run python scripts/gen_docs.py` — CI fails if stale), then update
    the platform table in CLAUDE.md, the README status, the user-guide
    support matrix, and the runtime templates in `integrations/`
    (drift-guarded by `integrations/test_integrations_valid.py`).
12. **Verify** — `uv run pytest`, `uv run ruff check .`, `uv run mypy .`, no
    real `.env` staged, conventional commit. **If you changed any tool, tool
    docstring/signature, or skill** (not just when adding a platform), rerun
    `uv run python scripts/gen_docs.py` and commit the regenerated
    `docs/reference/` — the CI drift guard (`scripts/tests/test_gen_docs.py`)
    fails on stale reference docs.

Gated write actions (only where operationally worth the risk) route through
`core/gating/` — never a hand-rolled confirmation. Study
`projectachilles-actions-mcp` as the reference consumer.

## Development workflow

- **Language:** Python 3.11+. Tooling: `uv`, `pytest`, `ruff`.
- **Commits:** Conventional Commits (e.g. `feat(tenable): add alert query tool`).
- **Tests must pass** (`pytest`) and code must lint (`ruff check`) before a PR.
- Stage specific files; never `git add -A` (avoid committing `.env*` or local
  data).

## Testing bar

- **Contract tests** are mandatory for every tool (mocked APIs, deterministic).
- The **small-model tool-calling eval** is built alongside every server and
  expected for new tools. If a tool passes contract tests but a small model
  cannot reliably call it, the tool's design is wrong — simplify the schema.

## License

By contributing, you agree your contributions are licensed under the Apache
License 2.0, consistent with the rest of the project.
