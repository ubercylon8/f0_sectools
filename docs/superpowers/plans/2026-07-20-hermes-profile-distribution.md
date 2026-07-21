# Hermes Profile Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `integrations/hermes/distribution/` — a git-installable Hermes profile distribution that stands up the validated `f0sectools` security agent via `hermes profile install`.

**Architecture:** A distribution directory (`distribution.yaml` manifest + `mcp.json` + `config.yaml` + `SOUL.md`) whose MCP commands and skill paths resolve `${F0_SECTOOLS_DIR}` at runtime. Secrets stay in per-repo `.env.<platform>`. The drift-guard test is extended to keep the distribution in sync with `servers/*`.

**Tech Stack:** Hermes Agent v0.18.2 profile-distribution feature, `uv`, PyYAML, pytest.

**Design spec:** `docs/superpowers/specs/2026-07-20-hermes-profile-distribution-design.md` (read for full rationale).

## Global Constraints

- **Approach A (clone-based `${F0_SECTOOLS_DIR}`).** No packaging change; servers keep running via `uv run --directory ${F0_SECTOOLS_DIR} f0-<x>-mcp`.
- **The distribution ships NO secrets** — `env_requires` documents only `F0_SECTOOLS_DIR`; per-platform credentials stay in `.env.<platform>` at the repo root.
- **Skills are one portable set** — loaded via `skills.external_dirs: ["${F0_SECTOOLS_DIR}/skills"]`, never copied.
- **Placeholders only** in committed files — `${F0_SECTOOLS_DIR}`, never a real local path (`test_templates_use_placeholder_paths_only` enforces this).
- **The 7 servers** are exactly the `[project.scripts]` names: `f0-defender`, `f0-entra`, `f0-limacharlie`, `f0-projectachilles`, `f0-pa-actions` (`f0-projectachilles-actions-mcp`), `f0-intune`, `f0-tenable`.
- **`config.example.yaml` is NOT drifted** — keep it; repoint its path to `${F0_SECTOOLS_DIR}`.

---

### Task 1: Distribution manifest + SOUL move

**Files:**
- Create: `integrations/hermes/distribution/distribution.yaml`
- Move: `integrations/hermes/SOUL.md` → `integrations/hermes/distribution/SOUL.md`
- Modify: `integrations/hermes/README.md` (point to the distribution + new SOUL location)
- Test: `integrations/test_integrations_valid.py` (new `test_distribution_manifest_valid`)

**Interfaces:**
- Produces: `integrations/hermes/distribution/distribution.yaml` with keys `name: f0sectools`, `version`, `description`, `hermes_requires`, `env_requires: [{name: F0_SECTOOLS_DIR, ...}]`.

- [ ] **Step 1: Write the failing test** in `integrations/test_integrations_valid.py`:

```python
def test_distribution_manifest_valid():
    import yaml
    manifest = yaml.safe_load(
        (ROOT / "integrations/hermes/distribution/distribution.yaml").read_text(encoding="utf-8")
    )
    assert manifest["name"] == "f0sectools"
    assert manifest.get("version")
    assert manifest.get("hermes_requires")
    env_names = {e["name"] for e in manifest.get("env_requires", [])}
    assert "F0_SECTOOLS_DIR" in env_names, "manifest must document F0_SECTOOLS_DIR"
    # No platform secrets are ever documented as required env (they live in .env.<platform>).
    assert not (env_names & {"DEFENDER_CLIENT_SECRET", "PROJECTACHILLES_API_KEY", "LC_API_KEY"})
```

- [ ] **Step 2: Run it — expect FAIL** (`FileNotFoundError` / `ROOT` unresolved):

Run: `uv run pytest integrations/test_integrations_valid.py::test_distribution_manifest_valid -v`
Expected: FAIL (distribution.yaml does not exist yet). If `ROOT` isn't defined in the test module, reuse the module's existing repo-root constant.

- [ ] **Step 3: Create `integrations/hermes/distribution/distribution.yaml`:**

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

- [ ] **Step 4: Move SOUL.md** (preserve history):

```bash
git mv integrations/hermes/SOUL.md integrations/hermes/distribution/SOUL.md
```

- [ ] **Step 5: Update `integrations/hermes/README.md`** to point at `distribution/` as the install path and note `SOUL.md` now lives under `distribution/`. Keep it short; link to `docs/user-guide/runtimes/hermes.md`.

- [ ] **Step 6: Run the test — expect PASS.**

Run: `uv run pytest integrations/test_integrations_valid.py::test_distribution_manifest_valid -v`
Expected: PASS.

- [ ] **Step 7: Commit.**

```bash
git add integrations/hermes/distribution/distribution.yaml integrations/hermes/distribution/SOUL.md integrations/hermes/README.md integrations/test_integrations_valid.py
git commit -m "feat(hermes): distribution manifest + move SOUL into the distribution"
```

---

### Task 2: Distribution `mcp.json` + extend the drift-guard

**Files:**
- Create: `integrations/hermes/distribution/mcp.json`
- Modify: `integrations/test_integrations_valid.py` (new `test_every_server_wired_into_distribution` + extend the placeholder test)
- Reference: `integrations/test_integrations_valid.py::_server_scripts()` (already returns the 7 `[project.scripts]` names), `test_every_server_wired_into_hermes_template` (mirror it)

**Interfaces:**
- Consumes: `_server_scripts()` → `{"f0-defender-mcp", "f0-entra-mcp", …}` (the entry-point names).
- Produces: `distribution/mcp.json` = `{"servers": {"<name>": {"command": "uv", "args": ["run", "--directory", "${F0_SECTOOLS_DIR}", "<entry-point>"]}}}`. **Top-level `servers` key** per the installer's test fixture (`{"servers": {}}`); the runtime→`mcp_servers` mapping is confirmed live in Task 6.

- [ ] **Step 1: Write the failing test** in `integrations/test_integrations_valid.py`. Mirror `test_every_server_wired_into_hermes_template`, but read the distribution `mcp.json` and its `servers` map, and derive server keys from the args' entry-point (the last arg):

```python
def _wired_from_dist(servers: dict) -> set[str]:
    # Each server's entry point is the last arg (e.g. "f0-defender-mcp").
    return {s["args"][-1] for s in servers.values()}


def test_every_server_wired_into_distribution():
    import json
    mcp = json.loads((ROOT / "integrations/hermes/distribution/mcp.json").read_text("utf-8"))
    assert _wired_from_dist(mcp["servers"]) == _server_scripts(), (
        "integrations/hermes/distribution/mcp.json is out of sync with servers/*"
    )
    # Every server runs from the F0_SECTOOLS_DIR placeholder, never a real path.
    for s in mcp["servers"].values():
        assert "${F0_SECTOOLS_DIR}" in s["args"], s
```

- [ ] **Step 2: Extend `test_templates_use_placeholder_paths_only`** to include `integrations/hermes/distribution/mcp.json` in its file list, and accept `${F0_SECTOOLS_DIR}` as the placeholder token (it must contain no `/home/`, no absolute real path). If the existing test asserts a specific placeholder string, add `${F0_SECTOOLS_DIR}` as an allowed token.

- [ ] **Step 3: Run — expect FAIL** (mcp.json missing):

Run: `uv run pytest integrations/test_integrations_valid.py -k "distribution or placeholder" -v`
Expected: FAIL.

- [ ] **Step 4: Create `integrations/hermes/distribution/mcp.json`:**

```json
{
  "servers": {
    "f0-defender": {
      "command": "uv",
      "args": ["run", "--directory", "${F0_SECTOOLS_DIR}", "f0-defender-mcp"]
    },
    "f0-entra": {
      "command": "uv",
      "args": ["run", "--directory", "${F0_SECTOOLS_DIR}", "f0-entra-mcp"]
    },
    "f0-limacharlie": {
      "command": "uv",
      "args": ["run", "--directory", "${F0_SECTOOLS_DIR}", "f0-limacharlie-mcp"]
    },
    "f0-projectachilles": {
      "command": "uv",
      "args": ["run", "--directory", "${F0_SECTOOLS_DIR}", "f0-projectachilles-mcp"]
    },
    "f0-pa-actions": {
      "command": "uv",
      "args": ["run", "--directory", "${F0_SECTOOLS_DIR}", "f0-projectachilles-actions-mcp"]
    },
    "f0-intune": {
      "command": "uv",
      "args": ["run", "--directory", "${F0_SECTOOLS_DIR}", "f0-intune-mcp"]
    },
    "f0-tenable": {
      "command": "uv",
      "args": ["run", "--directory", "${F0_SECTOOLS_DIR}", "f0-tenable-mcp"]
    }
  }
}
```

- [ ] **Step 5: Run — expect PASS.**

Run: `uv run pytest integrations/test_integrations_valid.py -k "distribution or placeholder" -v`
Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add integrations/hermes/distribution/mcp.json integrations/test_integrations_valid.py
git commit -m "feat(hermes): distribution mcp.json wiring all 7 servers + drift-guard"
```

---

### Task 3: Distribution `config.yaml` (behaviour, not model)

**Files:**
- Create: `integrations/hermes/distribution/config.yaml`
- Modify: `integrations/test_integrations_valid.py` (new `test_distribution_config_valid`)
- Reference: current `integrations/hermes/config.example.yaml` `agent.personalities:` block (copy the 4 personas verbatim)

**Interfaces:**
- Produces: `distribution/config.yaml` with `skills.external_dirs`, `agent.personalities` (4), `agent.disabled_toolsets` (candidate list — finalized live in Task 6), and NO `model:`/`providers:`.

- [ ] **Step 1: Write the failing test** in `integrations/test_integrations_valid.py`:

```python
def test_distribution_config_valid():
    import yaml
    cfg = yaml.safe_load(
        (ROOT / "integrations/hermes/distribution/config.yaml").read_text("utf-8")
    )
    # Skills load from the checkout via the env placeholder — never copied, never a real path.
    assert cfg["skills"]["external_dirs"] == ["${F0_SECTOOLS_DIR}/skills"]
    # The 4 role personas ship with the distribution.
    assert {"ciso", "threat-hunter", "detection-engineer", "security-engineer"} <= set(
        cfg["agent"]["personalities"]
    )
    # Security-only lockdown is declared.
    assert cfg["agent"].get("disabled_toolsets"), "distribution must lock down general toolsets"
    # No operator-specific model config is baked in (config.yaml is preserved on update).
    assert "model" not in cfg and "providers" not in cfg
```

- [ ] **Step 2: Run — expect FAIL** (config.yaml missing).

Run: `uv run pytest integrations/test_integrations_valid.py::test_distribution_config_valid -v`
Expected: FAIL.

- [ ] **Step 3: Create `integrations/hermes/distribution/config.yaml`.** Copy the 4-persona `agent.personalities:` block **verbatim** from `integrations/hermes/config.example.yaml` (ciso / threat-hunter / detection-engineer / security-engineer). Structure:

```yaml
# f0_sectools distribution config — behaviour only. Preserved on update, so
# operator overrides (model/provider, extra personas) persist. Set your local
# model with `hermes -p f0sectools model`; set F0_SECTOOLS_DIR in this profile's
# .env (points at your uv-synced checkout).
skills:
  external_dirs:
    - ${F0_SECTOOLS_DIR}/skills

agent:
  # Security-only lockdown: expose the 7 MCP servers + skills, drop the general
  # shell/file/browser toolsets a read-only analyst does not need. The exact
  # bundle names are verified live in Task 6 (restart + probe); this is the
  # candidate set.
  disabled_toolsets:
    - hermes-cli
  personalities:
    ciso: >
      <copy verbatim from config.example.yaml>
    threat-hunter: >
      <copy verbatim from config.example.yaml>
    detection-engineer: >
      <copy verbatim from config.example.yaml>
    security-engineer: >
      <copy verbatim from config.example.yaml>
```

(The `<copy verbatim …>` markers mean: paste the exact existing persona text from `config.example.yaml`; do not paraphrase.)

- [ ] **Step 4: Run — expect PASS.**

Run: `uv run pytest integrations/test_integrations_valid.py::test_distribution_config_valid -v`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add integrations/hermes/distribution/config.yaml integrations/test_integrations_valid.py
git commit -m "feat(hermes): distribution config.yaml — personas, external_dirs, lockdown"
```

---

### Task 4: Repoint `config.example.yaml` to `${F0_SECTOOLS_DIR}`

**Files:**
- Modify: `integrations/hermes/config.example.yaml`

**Interfaces:**
- Consumes: the existing `test_every_server_wired_into_hermes_template` + `test_templates_use_placeholder_paths_only` (must still pass).

- [ ] **Step 1: Edit `config.example.yaml`** — replace every `/ABSOLUTE/PATH/TO/sec-tools` in the `mcp_servers:` args with `${F0_SECTOOLS_DIR}`, and replace the `skills.external_dirs` entry with `${F0_SECTOOLS_DIR}/skills`. Add an `agent.disabled_toolsets: [hermes-cli]` block (mirroring the distribution) with a one-line comment. Update the header comment to mention `${F0_SECTOOLS_DIR}` and point to the distribution as the packaged alternative.

- [ ] **Step 2: Run the drift-guard suite — expect PASS.**

Run: `uv run pytest integrations/test_integrations_valid.py -v`
Expected: PASS (all wiring + placeholder tests green, including the new distribution ones).

- [ ] **Step 3: Commit.**

```bash
git add integrations/hermes/config.example.yaml
git commit -m "docs(hermes): repoint config.example.yaml to \${F0_SECTOOLS_DIR} + lockdown"
```

---

### Task 5: User-guide + install-flow docs

**Files:**
- Modify: `docs/user-guide/runtimes/hermes.md`

- [ ] **Step 1: Rewrite the setup section** of `docs/user-guide/runtimes/hermes.md` to lead with the distribution install and keep the manual-merge path as an alternative. Use the exact flow from the spec §"Install flow":
  1. clone + `uv sync --all-packages`
  2. create `.env.<platform>` files at the repo root
  3. `hermes profile install ./integrations/hermes/distribution`
  4. set `F0_SECTOOLS_DIR` in `~/.hermes/profiles/f0sectools/.env`
  5. `hermes -p f0sectools model` → local endpoint
  6. `f0sectools chat`
  Note the security-only lockdown and that gated writes stay off unless `PROJECTACHILLES_ALLOW_WRITE=true`. Use placeholder paths only.

- [ ] **Step 2: Link check.**

Run: `uv run pytest -k skills_valid` is unrelated; instead verify no broken in-repo links by inspection, and rely on CI `lychee`.

- [ ] **Step 3: Commit.**

```bash
git add docs/user-guide/runtimes/hermes.md
git commit -m "docs(hermes): profile-distribution install flow in the user guide"
```

---

### Task 6: Live verification + fix-forward (controller-executed, needs Hermes + GPU)

> **Not a subagent task.** This runs the real Hermes CLI against a throwaway profile on the box with Qwen on :8081. The controller executes it; it resolves the 3 open items and fix-forwards any file corrections into the earlier tasks' files.

**Files:** potentially `distribution/mcp.json`, `distribution/config.yaml` (fix-forward if live behaviour differs).

- [ ] **Step 1: Install into a throwaway profile.**

```bash
hermes profile install ./integrations/hermes/distribution --name f0sectools-dist-test
```
Confirm the exact invocation works (Open Item 3). If a subdir source is rejected, document the working form.

- [ ] **Step 2: Point it at the local model + set the env var.**

Set `F0_SECTOOLS_DIR` in `~/.hermes/profiles/f0sectools-dist-test/.env`; set the model to the local `:8081` endpoint.

- [ ] **Step 3: Verify servers connect (Open Item 2 — mcp.json → mcp_servers mapping).**

```bash
hermes -p f0sectools-dist-test mcp list
```
Expected: all 7 servers listed/enabled. **If they are absent,** the `mcp.json` `servers` shape/mapping is wrong → fix-forward: adjust `distribution/mcp.json` (or move the servers into `distribution/config.yaml` under `mcp_servers:` if mcp.json is not auto-loaded) and re-run. Update Task 2's file + test accordingly.

- [ ] **Step 4: Verify skills + personas + lockdown (Open Item 1 — disabled_toolsets).**

- Skills: `hermes -p f0sectools-dist-test skills list` shows the 22 f0 skills.
- Lockdown: a one-shot probe asking the agent to run a shell command must find **no terminal tool**, while a security tool still works. If shell survives OR skills/MCP break, adjust `disabled_toolsets` in `distribution/config.yaml` (bundle name vs explicit sub-toolset list) and repeat until security-only holds with MCP + skills intact. Update Task 3's file.

- [ ] **Step 5: Tear down the throwaway profile.**

```bash
hermes profile delete f0sectools-dist-test
```

- [ ] **Step 6: Commit any fix-forward changes.**

```bash
git add -A integrations/hermes/distribution
git commit -m "fix(hermes): reconcile distribution with live install (mcp.json/lockdown)"
```

---

## Verification (whole branch)

- [ ] `uv run pytest` — full offline suite green (incl. the 3 new distribution tests + existing drift-guard).
- [ ] `uv run ruff check .` and `uv run mypy .` — clean.
- [ ] Live install into a throwaway profile succeeded, 7 servers connected, 22 skills loaded, personas switched, lockdown held (Task 6).
- [ ] No real local paths in any committed file (`grep -rn '/home/' integrations/hermes/ docs/user-guide/runtimes/hermes.md` → none).
