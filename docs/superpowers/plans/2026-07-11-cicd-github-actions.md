# CI/CD via GitHub Actions — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add GitHub Actions CI/CD to f0_sectools — test+lint gate, secret scanning, SAST, dependency audit, link check, and comment-only Claude PR review — the automated gates needed before going public.

**Architecture:** Seven single-purpose workflow files under `.github/workflows/` plus a `.github/dependabot.yml`. Config only — no changes to `core/`, servers, tests, or tool code. CI is fully offline (`uv run pytest` collects only `test_*` files; live smokes stay local). Verification is push-and-observe: the checks run on the PR.

**Tech Stack:** GitHub Actions YAML, `uv` (astral-sh/setup-uv), gitleaks, semgrep, CodeQL, pip-audit, lychee, `anthropics/claude-code-action@v1`, Dependabot.

## Global Constraints

- **CI is offline.** `uv run pytest` (130 tests) never calls a live platform/model; no platform creds in CI. Do NOT add live-eval or live-smoke steps.
- **Hard gates:** `ci` (pytest + ruff), `secret-scan` (gitleaks), `semgrep`. **Informational/non-required:** `deps` (pip-audit), `links` (lychee), `codeql` (dormant on private), `claude-review` (var-gated, comment-only). The operator marks only the hard gates as *required* status checks in branch protection.
- **mypy is NOT a gate** — 53 pre-existing strict errors; run it `continue-on-error: true` (informational).
- **CodeQL needs GitHub Advanced Security on private repos** — gate the job `if: github.event.repository.private == false` (push + PR triggers only; NOT schedule, where that context is unreliable). Dormant now, auto-active on going public.
- **Claude review:** GitHub forbids `secrets` in `if:`, so gate the job on a repo **variable** `if: vars.ENABLE_CLAUDE_REVIEW == 'true'` (skipped-green until enabled). Needs `ANTHROPIC_API_KEY` secret (operator adds). Comment-only. Do NOT use `pull_request_target` (would run untrusted fork code with secret access).
- **Action versions** use major tags (`@v4`, `@v2`, `@v3`, `@v1`); Dependabot's `github-actions` ecosystem keeps them updated. (SHA-pinning is a hardening follow-up.)
- **Local pre-check:** no `actionlint` available — validate each YAML with `python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))"` before commit.
- **Commit style:** conventional commits ending with the two trailer lines exactly:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm`
  Stage specific files; never `git add -A`. Do not push (push is user-gated — Task 5).

---

### Task 1: Core CI gate (ci.yml)

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true
      - name: Install workspace
        run: uv sync --all-packages
      - name: Tests (offline — no live platform/model)
        run: uv run pytest
      - name: Lint
        run: uv run ruff check .
      - name: Type check (informational — mypy debt not yet a gate)
        run: uv run mypy .
        continue-on-error: true
```

- [ ] **Step 2: Validate YAML locally**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo OK`
Expected: `OK` (no YAML syntax error).

- [ ] **Step 3: Sanity-check the commands run locally (the CI will run these)**

Run: `uv run pytest -q && uv run ruff check . && echo "gate-cmds-pass"`
Expected: tests pass, ruff clean, prints `gate-cmds-pass`. (Confirms the CI's hard-gate commands actually pass on the current tree.)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add core test+lint workflow (mypy informational)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 2: Secret scan + SAST (secret-scan.yml, semgrep.yml)

**Files:**
- Create: `.github/workflows/secret-scan.yml`, `.github/workflows/semgrep.yml`

- [ ] **Step 1: Write secret-scan.yml**

Create `.github/workflows/secret-scan.yml`:

```yaml
name: Secret scan

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history so a secret in any commit is caught
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          # Personal account (ubercylon8) needs no GITLEAKS_LICENSE.
          # If the repo ever moves to a GitHub org, add a free GITLEAKS_LICENSE secret.
```

- [ ] **Step 2: Write semgrep.yml**

Create `.github/workflows/semgrep.yml`:

```yaml
name: Semgrep

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  semgrep:
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4
      - name: Semgrep scan
        run: semgrep scan --config p/python --config p/security-audit --error --skip-unknown-extensions
```

- [ ] **Step 3: Validate both YAMLs**

Run:
```bash
for f in secret-scan semgrep; do python3 -c "import yaml; yaml.safe_load(open('.github/workflows/$f.yml'))" && echo "$f OK"; done
```
Expected: `secret-scan OK` and `semgrep OK`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/secret-scan.yml .github/workflows/semgrep.yml
git commit -m "ci: add gitleaks secret scan and semgrep SAST

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 3: CodeQL (public-gated), deps audit, link check

**Files:**
- Create: `.github/workflows/codeql.yml`, `.github/workflows/deps.yml`, `.github/workflows/links.yml`

- [ ] **Step 1: Write codeql.yml (dormant on private, auto-active on public)**

Create `.github/workflows/codeql.yml`:

```yaml
name: CodeQL

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    # Code scanning needs GitHub Advanced Security on PRIVATE repos (free on public).
    # This job is skipped (green) while the repo is private and activates automatically
    # once it is public. push + pull_request only — repository.private is unreliable on schedule.
    if: github.event.repository.private == false
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: python
      - uses: github/codeql-action/analyze@v3
```

- [ ] **Step 2: Write deps.yml (pip-audit, informational)**

Create `.github/workflows/deps.yml`:

```yaml
name: Dependency audit

on:
  pull_request:
  schedule:
    - cron: "0 6 * * 1"  # Mondays 06:00 UTC

permissions:
  contents: read

jobs:
  pip-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - name: Export resolved deps
        run: uv export --format requirements-txt --no-hashes --all-packages > requirements-audit.txt
      - name: pip-audit (informational — Dependabot files the fix PRs)
        run: uvx pip-audit -r requirements-audit.txt
        continue-on-error: true
```

- [ ] **Step 3: Write links.yml (lychee, non-blocking)**

Create `.github/workflows/links.yml`:

```yaml
name: Link check

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  lychee:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: lycheeverse/lychee-action@v2
        with:
          args: "--no-progress './**/*.md'"
          fail: false  # external links rot; report, don't block
```

- [ ] **Step 4: Validate all three YAMLs**

Run:
```bash
for f in codeql deps links; do python3 -c "import yaml; yaml.safe_load(open('.github/workflows/$f.yml'))" && echo "$f OK"; done
```
Expected: `codeql OK`, `deps OK`, `links OK`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/codeql.yml .github/workflows/deps.yml .github/workflows/links.yml
git commit -m "ci: add CodeQL (public-gated), pip-audit, and lychee link check

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 4: Claude review + Dependabot

**Files:**
- Create: `.github/workflows/claude-review.yml`, `.github/dependabot.yml`

- [ ] **Step 1: Write claude-review.yml (var-gated, comment-only)**

Create `.github/workflows/claude-review.yml`:

```yaml
name: Claude review

on:
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write
  id-token: write

jobs:
  review:
    # Enable by BOTH: set repo variable ENABLE_CLAUDE_REVIEW=true AND add the
    # ANTHROPIC_API_KEY secret. Secrets can't be used in `if:`, so we gate on the
    # variable (skipped-green until enabled). Does NOT run on fork PRs (no secret access);
    # we deliberately avoid pull_request_target for security.
    if: vars.ENABLE_CLAUDE_REVIEW == 'true'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 1
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: |
            REPO: ${{ github.repository }}
            PR NUMBER: ${{ github.event.pull_request.number }}

            Review this pull request for f0_sectools, a security-tooling repo (MCP servers
            + skills for security platforms, driven by small local models). Focus on:
            - Correctness and potential bugs.
            - Security: this repo handles per-platform credentials and gated write actions —
              flag any secret that could leak into output/logs, any write not behind the
              flag+token gate, or missing redaction.
            - Adherence to the Critical Rules in CLAUDE.md (read-only by default, secrets
              never leave the host, redact before returning, small-model-safe flat tool schemas).
            - Test coverage for changed logic.

            The PR branch is checked out in the working directory.
            Use `gh pr comment` for top-level feedback and inline comments for specific issues.
            Only post GitHub comments — don't submit review text as chat messages.
          claude_args: |
            --allowedTools "mcp__github_inline_comment__create_inline_comment,Bash(gh pr comment:*),Bash(gh pr diff:*),Bash(gh pr view:*)"
```

- [ ] **Step 2: Write dependabot.yml**

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "uv"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

- [ ] **Step 3: Validate both YAMLs**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/claude-review.yml'))" && echo "claude OK"
python3 -c "import yaml; yaml.safe_load(open('.github/dependabot.yml'))" && echo "dependabot OK"
```
Expected: `claude OK` and `dependabot OK`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/claude-review.yml .github/dependabot.yml
git commit -m "ci: add comment-only Claude PR review (var-gated) and Dependabot

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 5: Docs + push-and-observe verification

**Files:**
- Modify: `CLAUDE.md` (Development Workflow / Testing section)

- [ ] **Step 1: Document the CI in CLAUDE.md**

In `CLAUDE.md`, in the "Testing & Evaluation" or "Development Workflow" area, add a short subsection (match the surrounding style):

```markdown
### Continuous Integration (GitHub Actions)

Every push/PR runs (`.github/workflows/`):
- **ci** — `uv run pytest` (130 offline tests) + `uv run ruff check .` (**hard gate**); mypy runs informational (its strict errors aren't a gate yet).
- **secret-scan** (gitleaks) and **semgrep** (SAST) — **hard gates**.
- **deps** (pip-audit), **links** (lychee), **codeql** (dormant until the repo is public), **claude-review** (comment-only) — advisory, not required checks.

Live-model evals and live-platform smoke scripts are **never** run in CI (no creds/GPU) — they stay local. Mark only `ci`, `secret-scan`, and `semgrep` as required status checks in branch protection.

**To enable Claude PR review:** add an `ANTHROPIC_API_KEY` repository secret and set the repository variable `ENABLE_CLAUDE_REVIEW=true`. It posts advisory comments; it does not block merge and does not run on fork PRs (no secret access).
```

- [ ] **Step 2: Full local verification of everything committed so far**

Run: `uv run pytest -q && uv run ruff check . && echo "local-green"`
Expected: `local-green`. Then confirm all eight new files exist and parse:
```bash
ls .github/workflows/*.yml .github/dependabot.yml | wc -l   # expect 8
for f in .github/workflows/*.yml .github/dependabot.yml; do python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" "$f" || echo "BAD: $f"; done; echo "yaml-ok"
```
Expected: `8`, then `yaml-ok` with no `BAD:` lines.

- [ ] **Step 3: Commit the docs**

```bash
git add CLAUDE.md
git commit -m "docs: document the CI gates and Claude-review enablement in CLAUDE.md

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

- [ ] **Step 4: Push + open PR + OBSERVE (push is user-gated)**

> Workflows can't be verified locally — they only run once pushed. This step needs the user's push authorization (house rule). After pushing and opening the PR, read the check results:
> - **Expect green:** `ci`, `secret-scan`, `semgrep`, `links`.
> - **Expect skipped:** `codeql` (repo is private), `claude-review` (variable not set).
> - **`deps`** green (pip-audit is `continue-on-error`).
> Fix any genuinely red check (e.g. a semgrep finding on real code, a gitleaks false positive → add an inline `gitleaks:allow` or a `.gitleaksignore`) and re-push. Report the final check matrix.

Verify with: `gh pr checks <pr-number>` (after the PR exists) and iterate until the expected matrix holds.

---

## Self-Review

**Spec coverage:**
- ci (test+lint hard gate, mypy informational) → Task 1. ✓
- secret-scan (gitleaks) + semgrep (SAST) hard gates → Task 2. ✓
- codeql (public-gated), deps (pip-audit informational), links (lychee fail:false) → Task 3. ✓
- claude-review (var-gated, comment-only, ANTHROPIC_API_KEY) + dependabot (uv + github-actions) → Task 4. ✓
- Docs (CI gates, required-checks guidance, Claude enablement, live-tests-stay-local) → Task 5. ✓
- Offline-only CI; no live calls → Global Constraints + Task 1 note. ✓
- Fork-PR / secrets-in-`if:` limitations handled → Task 4 comments + Global Constraints. ✓
- Verification = push-and-observe (user-gated) → Task 5 Step 4. ✓

**Placeholder scan:** No TBD/TODO. Every workflow's full YAML is given verbatim. Task 5 doc prose is copy, not code.

**Consistency:** All eight file paths are consistent across tasks and the file table. `astral-sh/setup-uv@v5`, `actions/checkout@v4`, `gitleaks/gitleaks-action@v2`, `github/codeql-action/*@v3`, `lycheeverse/lychee-action@v2`, `anthropics/claude-code-action@v1` used consistently. The `ENABLE_CLAUDE_REVIEW` variable and `ANTHROPIC_API_KEY` secret names match between Task 4 YAML and Task 5 docs. The three hard-gate check names (`ci`, `secret-scan`, `semgrep`) match between Global Constraints and Task 5 docs.
