# opencode Runtime Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire opencode (≥1.18) as a runtime: repo-root project `opencode.json` (7 MCP servers, pa-actions disabled), `.opencode/skills/` symlinks (native SKILL.md loading), `.opencode/agents/` persona files, drift-guard tests, docs.

**Architecture:** In-repo project config per the spec (`docs/superpowers/specs/2026-07-21-opencode-runtime-design.md`). No skill-content forks (Critical Rule 9); wiring only.

**Tech stack:** JSON config, git symlinks, pytest drift guards, markdown agents.

## Global Constraints

- Gated-write server `f0-pa-actions` MUST ship `"enabled": false` (forge-resistance gap — model has shell).
- No real local paths in any committed file; relative paths only.
- No `model`/`provider` keys in the project config (never touch the operator's setup).
- Skill symlinks named exactly by each skill's frontmatter `name`.
- Persona agent files carry identity + lens; no skill-content duplication.

---

### Task 1: Skill symlinks + drift guard

**Files:** Create `.opencode/skills/<name>` (22 relative symlinks); Modify `integrations/test_integrations_valid.py`.

- [ ] Write failing test `test_opencode_skill_symlinks_complete_and_valid`: for every `skills/*/*/SKILL.md`, parse frontmatter `name`; assert `.opencode/skills/<name>` exists, is a symlink, resolves to that skill dir; assert no extra entries.
- [ ] Generate the symlinks (python one-liner over the same frontmatter parse; `os.symlink` relative targets `../../skills/<platform>/<skill>`).
- [ ] `uv run pytest integrations/ -q` → PASS. Commit.

### Task 2: Project opencode.json + drift guard

**Files:** Create `opencode.json` (repo root); Modify `integrations/test_integrations_valid.py`.

- [ ] Write failing tests: `test_every_server_wired_into_opencode_config` (`_wired(cfg["mcp"]) == _server_scripts()`, commands use `["uv","run","--directory",".",<script>]`), assert `cfg["mcp"]["f0-pa-actions"]["enabled"] is False`, no `/home/`//`/Users/` strings, no `model`/`provider` keys; add `opencode.json` to the no-real-paths file set.
- [ ] Create `opencode.json`: `$schema`, `mcp` block (7 servers, pa-actions disabled), `permission.skill: {"*": "allow"}`.
- [ ] Tests PASS. Commit.

### Task 3: Persona agent files

**Files:** Create `.opencode/agents/{ciso,threat-hunter,detection-engineer,security-engineer}.md` + `integrations/opencode/README.md`.

- [ ] Each agent file: frontmatter `description` + `mode: primary`; body = shared identity block (adapted from `integrations/pi/AGENTS.md`: read-only, never fabricate, one tool at a time, relay degradation, ground in evidence, findings-shaped output) + persona lens (adapted from `integrations/pi/prompts/<persona>.md`, `$ARGUMENTS` mechanics removed, skill references kept by name).
- [ ] `integrations/opencode/README.md`: layout pointer (wiring lives in `/opencode.json` + `/.opencode/`; why in-repo; the gated-write caveat; Windows symlink note).
- [ ] Commit.

### Task 4: Verify-live list (operator's machine, read-only)

- [ ] With a local model endpoint up, in the checkout run `opencode` / `opencode run`: skills discovered via symlinks (incl. `version:` frontmatter tolerance); MCP servers listed, tool round-trip works (cwd/.env resolution); `f0-pa-actions` absent while `enabled:false`; 4 agents switchable.
- [ ] Read-only sweep: one representative question per enabled server on Qwen3.5-9B.
- [ ] Fix-forward failures per the spec's fallback table. Commit fixes.

### Task 5: Docs + matrix flip

**Files:** Create `docs/user-guide/runtimes/opencode.md`; Modify `docs/user-guide/README.md`, `CLAUDE.md`, `CHANGELOG.md`.

- [ ] Runtime guide: run-from-checkout quickstart, agents, skills, gated-write caveat + `PROJECTACHILLES_ALLOW_WRITE=false` instruction, Windows note, troubleshooting.
- [ ] Support matrix: opencode row → `✅ native` / `✅ agent files` / stdio / guide link; legend updated.
- [ ] CLAUDE.md runtimes bullet + architecture tree; CHANGELOG `[Unreleased]` Added entry.
- [ ] `uv run pytest && uv run ruff check . && uv run mypy .` all clean. Commit.
