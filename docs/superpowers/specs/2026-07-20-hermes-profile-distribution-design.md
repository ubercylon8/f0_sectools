# f0_sectools Hermes Profile Distribution — Design (Phase B)

**Date:** 2026-07-20
**Status:** Design (awaiting review)
**Parent:** `2026-07-20-hermes-runtime-integration-design.md` (§4) — Phase A is complete.

**Goal:** Package the live-validated `f0sectools` Hermes profile as a
**git-installable profile distribution** so an operator runs one install command
and gets the whole security agent (7 MCP servers + 22 skills + 4 personas + SOUL),
keeping their own keys, memory, and sessions.

**Architecture:** A distribution directory in the repo
(`integrations/hermes/distribution/`) holding a `distribution.yaml` manifest plus
`mcp.json`, `config.yaml`, and `SOUL.md`. The operator clones the repo (needed
for the per-platform `.env` files regardless), sets one env var
(`F0_SECTOOLS_DIR`), and runs `hermes profile install`. MCP server commands and
skill paths resolve `${F0_SECTOOLS_DIR}` at runtime. **Secrets never leave the
repo `.env.<platform>` files** — the distribution ships none.

**Tech stack:** Hermes Agent v0.18.2 profile-distribution feature
(`hermes profile install`), `uv`, the existing `f0_sectools` workspace.

## Global Constraints

- **Approach A (clone-based `${F0_SECTOOLS_DIR}`)** — decided with the operator.
  No packaging change; servers keep running via `uv run --directory`. The
  pip-installable alternative (Approach B) is explicitly rejected: it would force
  secrets out of the per-repo `.env` model (Critical Rules 2/7) and contradicts
  CLAUDE.md's YAGNI-on-packaging.
- **Secrets stay in `.env.<platform>` at the repo root**, loaded by each server
  via `uv run --directory`. The distribution documents only `F0_SECTOOLS_DIR` in
  `env_requires`; it never lists or ships platform credentials.
- **Skills are one portable set (Rule 9)** — loaded via
  `skills.external_dirs: ["${F0_SECTOOLS_DIR}/skills"]`, never copied into the
  distribution.
- **Templates carry placeholders only** — `${F0_SECTOOLS_DIR}`, never a real
  local path (enforced by `test_templates_use_placeholder_paths_only`).
- **`config.example.yaml` is NOT drifted** and is kept (the manual-merge path).
  `mcp_servers:` is a real config key; `mcp.json` is its distribution-file form.

## Verified facts (installed Hermes v0.18.2 source)

- **Distribution format** (`hermes_cli/profile_distribution.py`): manifest
  `distribution.yaml` at the source root; distribution-owned files default to
  `SOUL.md`, `config.yaml`, `mcp.json`, `skills/`, `cron/`, `distribution.yaml`.
  `config.yaml` is distribution-owned but **preserved** on update (unless
  `--force-config`); `mcp.json`/`SOUL.md`/`skills/` are **replaced** on update.
  User-owned paths (`.env`, `auth.json`, `memories/`, `sessions/`, `state.db`,
  …) are never touched.
- **Manifest schema:** `name` (required), `version`, `description`, `author`,
  `license`, `hermes_requires`, `env_requires: [{name, description, required,
  default}]`, optional `distribution_owned:`.
- **`${ENV}` expansion:** MCP server configs are interpolated before connecting
  (`mcp_config.py:_resolve_mcp_server_config` → `_interpolate_env_vars`), loading
  the profile `.env` first. `skills.external_dirs` entries expand `${ENV}` and
  `~` (`skill_utils.py:493`). So `${F0_SECTOOLS_DIR}` resolves from the profile
  `.env` at runtime.
- **`mcp_servers` map:** stored under the top-level `mcp_servers:` key in the
  profile `config.yaml`; `mcp.json` is the standalone-file form of that same map
  (`web_server.py`).

---

## Components — `integrations/hermes/distribution/`

### 1. `distribution.yaml`

```yaml
name: f0sectools
version: 0.1.0
description: >
  F0RT1KA security-operations agent — read-only SOC/IR/CISO tooling over
  Microsoft Defender, Entra ID, LimaCharlie, ProjectAchilles, Intune, and
  Tenable, driven by a local small model. Gated writes for ProjectAchilles
  validation runs (flag + human confirmation + audit).
author: F0RT1KA Contributors
license: Apache-2.0
hermes_requires: ">=0.18.0"
env_requires:
  - name: F0_SECTOOLS_DIR
    description: >
      Absolute path to your uv-synced f0_sectools checkout. The MCP servers run
      from here (uv run --directory) and load per-platform secrets from its
      .env.<platform> files — no credentials are stored in Hermes.
    required: true
```

### 2. `mcp.json` — the 7 servers (the `mcp_servers` map form)

Each server: `uv run --directory ${F0_SECTOOLS_DIR} f0-<x>-mcp`. Exact top-level
shape (bare `mcp_servers` map vs a wrapper key) is confirmed against the
installer during implementation; the profile stores them under `mcp_servers:`.
Servers: `f0-defender`, `f0-entra`, `f0-limacharlie`, `f0-projectachilles`,
`f0-pa-actions`, `f0-intune`, `f0-tenable` — derived from each
`servers/*/pyproject.toml` `[project.scripts]` name.

### 3. `config.yaml` — behaviour, NOT model

- `skills.external_dirs: ["${F0_SECTOOLS_DIR}/skills"]`
- `agent.personalities:` — the 4 role lenses (ciso / threat-hunter /
  detection-engineer / security-engineer), verbatim from the current
  `config.example.yaml`.
- `agent.disabled_toolsets:` — the **security-only lockdown**: drop the general
  bundles (shell/file/browser/web/computer-use) so the agent exposes only the 7
  MCP servers + skills. Exact list verified live (restart + probe) during
  implementation — see Open Items.
- **No `model:` / `providers:`** — the local endpoint is per-operator; they set
  it with `hermes model` (or their own `.env`). `config.yaml` is preserved on
  update, so operator model choices persist.

### 4. `SOUL.md`

The security identity — the existing `integrations/hermes/SOUL.md`, moved into
the distribution (single source; `integrations/hermes/README.md` points here).

---

## Repo changes outside the distribution dir

- **Keep `integrations/hermes/config.example.yaml`** as the manual-merge path.
  Repoint its placeholder `/ABSOLUTE/PATH/TO/sec-tools` to `${F0_SECTOOLS_DIR}`
  and add the `agent.disabled_toolsets` lockdown block, so it stays consistent
  with the distribution.
- **Extend the drift-guard** (`integrations/test_integrations_valid.py`): add a
  test asserting the distribution `mcp.json` wires exactly the 7
  `[project.scripts]` servers (mirroring the existing `config.example.yaml`
  test), and include `mcp.json` in `test_templates_use_placeholder_paths_only`.
- **User guide:** rewrite `docs/user-guide/runtimes/hermes.md`'s setup section
  to lead with the distribution install and keep the manual-merge path as an
  alternative. Update `integrations/hermes/README.md`.

## Install flow (documented for operators)

1. Clone the repo; `uv sync --all-packages`.
2. Create `.env.<platform>` files at the repo root (existing per-platform docs).
3. `hermes profile install ./integrations/hermes/distribution` (from the clone).
4. Set `F0_SECTOOLS_DIR=<abs path to clone>` in
   `~/.hermes/profiles/f0sectools/.env`.
5. `hermes -p f0sectools model` → point at the local OpenAI-compatible endpoint.
6. `f0sectools chat` (the install creates the wrapper alias).

## Testing

- **Offline (CI):** the extended drift-guard tests (7 servers wired in
  `mcp.json`; placeholders only); `distribution.yaml` parses and has the required
  manifest fields; `config.yaml` parses with the 4 personas + `external_dirs` +
  `disabled_toolsets`.
- **Live (local, not CI):** install the distribution into a throwaway profile
  (`--name f0sectools-dist-test`), confirm the 7 servers connect, 22 skills load,
  `/personality` switches, and the lockdown holds (shell tool absent) — mirroring
  Phase A's verification. Then remove the throwaway profile.

## Out of scope (YAGNI)

- `cron/` scheduled tasks.
- A bespoke installer script (`hermes profile install` + docs suffice).
- Publishing to a registry / `hermes profile install` from a git *subdirectory*
  URL (documented flow installs from the local clone's subdir).
- Model/provider config in the distribution (operator-specific).

## Open items (resolved during implementation, not guessed)

1. **`disabled_toolsets` exact list** — determine which bundle names give
   security-only while keeping MCP + skills + the ability to respond; verify by
   restart + probe (Phase A method). If a bundle name (e.g. `hermes-cli`)
   cleanly subtracts the general set, prefer it over enumerating sub-toolsets.
2. **`mcp.json` top-level shape** — confirm bare map vs wrapper key against the
   installer / an existing `mcp.json` before writing the file.
3. **`hermes profile install` from a subdir** — confirm the exact invocation for
   a distribution living in `integrations/hermes/distribution/` (local-dir
   install expected to work; git-URL-subdir may not).
