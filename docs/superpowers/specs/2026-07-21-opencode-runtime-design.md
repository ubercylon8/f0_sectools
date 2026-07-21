# opencode Runtime Integration — Design

**Date:** 2026-07-21 · **Status:** approved-pending-review · **Target:** opencode ≥ 1.18
(validated against 1.18.4)

Add [opencode](https://opencode.ai) (the open-source terminal AI agent) as a
supported runtime for the f0_sectools servers, skills, and personas — alongside
Hermes (primary), pi, Claude Code, LM Studio, and Open WebUI.

## Goal

An operator who runs `opencode` **inside the f0_sectools checkout** gets, with
no manual config merging:

- all **7 MCP servers** wired (gated-write server disabled by default),
- all **22 skills** loaded **natively** via opencode's own SKILL.md support,
- the **4 role personas** available as switchable agents,
- their personal opencode setup (providers, models, keybinds) untouched.

## Key research findings (2026-07-21, opencode 1.18.4)

1. **opencode has native SKILL.md skills** (`opencode.ai/docs/skills`), with
   progressive disclosure via a `skill` tool, permission gating
   (`permission.skill`), and multi-path discovery: `.opencode/skills/*/SKILL.md`
   (project, discovered by walking up to the git root), `.claude/skills/`,
   `.agents/skills/`, plus global equivalents. Frontmatter requires `name`
   (lowercase-hyphen, 1–64 chars) and `description` (≤1024 chars).
   *(Supersedes the earlier roadmap note that opencode had no skill system.)*
2. **Our 22 skills are already compatible**: every `name:` is globally unique
   and platform-prefixed (`defender-threat-hunt` vs `limacharlie-threat-hunt`),
   lowercase-hyphen conformant, with valid `description`s. No renames, no
   content changes, no forks (Critical Rule 9 holds).
3. **MCP**: project `opencode.json` takes an `mcp` block; a local server is
   `type: "local"` + a command array, with an `enabled` flag.
4. **Agents**: markdown files in `.opencode/agents/` (project scope) with YAML
   frontmatter (description, optional model/tools/permissions); switchable in
   the TUI.
5. **Delivery decision (user):** in-repo **project config** — not a
   global-config template. opencode auto-loads project config from the checkout.
6. The operator's machine already runs opencode 1.18.4 with local-model
   providers (llama.cpp :8081 Qwen3.5-9B among them) — Phase A validates
   against that.

## Design

### 1. Skills — committed relative symlinks (no bridge, no forks)

```
.opencode/skills/defender-triage-incident   -> ../../skills/defender/triage-incident
.opencode/skills/limacharlie-threat-hunt    -> ../../skills/limacharlie/threat-hunt
… (one per skill, named by the skill's frontmatter `name`)
```

- Symlink **directories**, so each skill's `SKILL.md` *and* its `references/`
  travel together.
- Committed to git as relative symlinks (POSIX; Windows checkout caveat
  documented in the runtime guide).
- **Drift guard:** a new test in `integrations/test_integrations_valid.py`
  asserts the symlink set ≡ the set of `skills/*/*/SKILL.md` frontmatter names,
  and that every link resolves. Adding skill #23 without a link = red CI.

### 2. Personas — 4 project agent files

`.opencode/agents/{ciso,threat-hunter,detection-engineer,security-engineer}.md`

- Frontmatter: `description` (one-line lens summary), `mode: primary` so they
  appear in the TUI agent switcher. **No `model:`** — the operator's default
  applies.
- Body = shared f0_sectools identity (adapted from `integrations/pi/AGENTS.md`:
  read-only, never fabricate, one tool at a time, relay degradation, ground in
  evidence) + that persona's lens (adapted from `integrations/pi/prompts/*.md`,
  minus pi's `$ARGUMENTS` mechanics, which don't apply).
- **No repo-root `AGENTS.md`**: other tools also read that file; identity stays
  scoped inside the agent files so opening this repo in another agent runtime
  is unaffected.

### 3. MCP — project `opencode.json` at the repo root

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "f0-defender":       { "type": "local", "command": ["uv", "run", "--directory", ".", "f0-defender-mcp"],       "enabled": true },
    // … entra, limacharlie, projectachilles, intune, tenable: same shape …
    "f0-pa-actions":     { "type": "local", "command": ["uv", "run", "--directory", ".", "f0-projectachilles-actions-mcp"], "enabled": false }
  },
  "permission": { "skill": { "*": "allow" } }
}
```

- **Relative paths only** (the config lives in the checkout) — no
  `${F0_SECTOOLS_DIR}`, no per-user rendering, no real paths in git.
- **`f0-pa-actions` ships `enabled: false`** — same rationale as the Hermes
  distribution: the opencode model has shell access, so the gated-write
  confirmation is **not forge-resistant**; writes are an explicit opt-in.
  Documented in the config comment-equivalent (JSON has no comments — the
  caveat lives in the runtime guide and the README) and enforced by the drift
  guard.
- **No `model`/`provider` keys** — never touch the operator's model setup.
- `.env.<platform>` files at the repo root are found because the servers run
  with `--directory .` (cwd = project root), matching pi/Hermes behaviour.

### 4. Docs & guard rails

- `docs/user-guide/runtimes/opencode.md` — install, run-from-checkout, agent
  switching, skills behaviour, the gated-write caveat, Windows symlink note.
- Support matrix: flip the `opencode (planned)` row to live
  (`✅ native` skills / `✅ agent files` personas / stdio).
- `integrations/opencode/README.md` — pointer doc (the real wiring lives in
  `.opencode/` + `opencode.json`; this README explains the layout so the
  integrations/ tree stays the index of runtime wiring).
- Drift guard extensions (`integrations/test_integrations_valid.py`):
  every workspace server wired into `opencode.json` `mcp`; `f0-pa-actions`
  `enabled` is `false`; no real local paths; skill symlink set complete + valid.
- CLAUDE.md: runtimes list + architecture tree gain opencode; CHANGELOG entry.

## Verify-live list (build-time, each with a sanctioned fallback)

| Unknown | Check | Fallback if it fails |
|---|---|---|
| Symlinked skill dirs are discovered | `opencode` in checkout → skills listed in the `skill` tool | generate stub dirs (`SKILL.md` that includes the real one by path) via a small sync script |
| Extra frontmatter keys (`version`, `metadata.hermes`) tolerated | same check | strip-nothing; if rejected, raise upstream + add minimal per-skill stub frontmatter (last resort — avoid) |
| MCP command cwd = project root (relative `--directory .` works; `.env.*` found) | tool call round-trip | absolute path via opencode config variable substitution, rendered by a sync script (pi pattern) |
| `enabled: false` honored (server absent until flipped) | server list in TUI | omit the pa-actions entry entirely + document manual add |
| Project agents appear + switch correctly | TUI agent list | global agents dir + sync script |

## Phases

- **Phase A — wire + local live validation** (this spec): create the files,
  drift-guard them, run the verify-live list against Qwen3.5-9B (llama.cpp
  :8081 — the `llama-qwen35` provider already configured on the operator's
  machine), then a read-only sweep (one representative question per server) in
  the checkout. Fix-forward shape mismatches per recipe step 9.
- **Phase B — docs + matrix flip + PR.** (Same PR unless Phase A uncovers
  structural surprises.)
- **Out of scope:** eval-scorecard runs under opencode; gated-write live
  testing under opencode (stays Hermes/pi for now); Windows validation.

## Security notes

- All Critical Rules hold unchanged: the servers are the same read-only
  binaries; redaction/gating live in `core/`; no secrets in any committed file.
- The **forge-resistance gap** applies to opencode exactly as documented for
  Hermes: the model can drive a shell, `confirm_action.py` has no operator
  auth, so chat-side confirmation could in principle be self-authorized. Hence
  gated writes ship disabled; the runtime guide repeats the caveat and the
  "keep `PROJECTACHILLES_ALLOW_WRITE=false` unless accepted" instruction.
- opencode's `permission` config (e.g. `"bash": "ask"`) *may* allow a stronger
  posture than Hermes v0.18.2 could offer; evaluating that is a Phase-A
  observation item, not a dependency.

## Testing

- Contract layer: the drift-guard tests above (offline, CI-gated).
- Live layer: the verify-live list + read-only sweep (operator-confirmed, not
  in CI), recorded in the PR body with identifiers redacted.
