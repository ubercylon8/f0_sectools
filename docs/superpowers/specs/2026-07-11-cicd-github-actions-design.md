# Design: CI/CD via GitHub Actions (gate before going public)

**Date:** 2026-07-11
**Status:** Approved (design), pending spec review
**Scope:** One implementation plan — `.github/` workflows + dependabot config + docs.

## Problem

f0_sectools has 130 tests, ruff (incl. bandit `S` rules), and a strict secrets discipline —
all enforced only on a developer's laptop today. The repo is Apache-2.0 and headed for public
release; accepting external PRs safely needs automated gates: tests/lint, secret scanning,
dependency + SAST scanning, and automated review. This adds them as GitHub Actions.

## Verified grounding facts (2026-07-11)

- No CI exists yet. Python ≥3.11, `uv` workspace. `uv run pytest` (130 tests) and
  `uv run ruff check .` both pass and are the intended **hard gate**.
- `uv run pytest` is **fully offline** — it collects only `test_*` files (fake clients); the
  `scripts/live_smoke_*.py` are not `test_*`, so pytest never calls a live platform/model. CI
  needs no platform creds.
- ruff already runs flake8-bandit (`S`) → **no separate bandit** step.
- mypy is `strict=true` but has **53 pre-existing errors** → **cannot be a hard gate**;
  informational only (follow-up: clean up, then gate).
- **CodeQL needs GitHub Advanced Security for private repos** (free only when public) → include
  it but gate the job to `repository.private == false` so it's dormant now, live on going public.
- **gitleaks-action** is free for personal accounts (`ubercylon8` is one); a free `GITLEAKS_LICENSE`
  is only needed if the repo moves to a GitHub **org**.
- **Verified action configs:** `anthropics/claude-code-action@v1` takes `anthropic_api_key`,
  `prompt`, `claude_args`; the automatic-review pattern posts comments via `gh pr comment`
  (comment-only, non-blocking). **Dependabot** supports `package-ecosystem: "uv"` (dir `/`) and
  `"github-actions"` (dir `/`).

## Decisions (from brainstorm)

- **Full stack now.** All workflows in one PR.
- **SAST = both:** semgrep now (free on private) + a CodeQL workflow dormant-until-public.
- **Claude review = comment-only**, `ANTHROPIC_API_KEY` repo secret (operator adds it; inert until then).

## Architecture — files

Seven single-purpose workflow files + one Dependabot config. Each is an isolated status check.

```
.github/
  dependabot.yml            # weekly: uv (Python deps) + github-actions
  workflows/
    ci.yml                  # HARD GATE: uv sync -> pytest + ruff; mypy informational (continue-on-error)
    secret-scan.yml         # HARD GATE: gitleaks on push + PR
    semgrep.yml             # HARD GATE: semgrep scan (p/python + p/security-audit), token-free
    codeql.yml              # gated `if: repository.private == false` — dormant on private, live on public
    deps.yml                # pip-audit on resolved deps; PR + weekly; NON-blocking (continue-on-error)
    links.yml               # lychee markdown link check; NON-blocking (external links go stale)
    claude-review.yml       # anthropics/claude-code-action@v1, comment-only, needs ANTHROPIC_API_KEY
```

## Per-workflow design

- **ci.yml** — `on: [push (main), pull_request]`. Steps: checkout → `astral-sh/setup-uv` →
  `uv sync --all-packages` → `uv run pytest` → `uv run ruff check .`. A separate step (or job)
  runs `uv run mypy .` with `continue-on-error: true` (informational; the 53 errors don't gate).
- **secret-scan.yml** — `on: [push, pull_request]`. `gitleaks/gitleaks-action@v2` with
  `fetch-depth: 0` so it scans full history on PRs. Hard gate — a committed secret blocks merge.
- **semgrep.yml** — `on: [push (main), pull_request]`. Run in the `semgrep/semgrep` container:
  `semgrep scan --config p/python --config p/security-audit --error` (token-free OSS rulesets).
  Hard gate.
- **codeql.yml** — `on: [push (main), pull_request, schedule (weekly)]`, job `if:
  github.event.repository.private == false`. `github/codeql-action` init(python)+analyze. Skips
  cleanly (green) while private; activates automatically once the repo is public.
- **deps.yml** — `on: [pull_request, schedule (weekly)]`. `uv export --format requirements-txt
  --no-hashes --all-packages > reqs.txt` → `uvx pip-audit -r reqs.txt`, `continue-on-error: true`
  (a transitive CVE shouldn't wedge unrelated PRs; Dependabot files the fix). Informational.
- **links.yml** — `on: [push (main), pull_request]`. `lycheeverse/lychee-action@v2` over
  `**/*.md`, `fail: false` (informational — external links rot). Catches broken relative links.
- **claude-review.yml** — `on: pull_request [opened, synchronize]`. `permissions: contents:read,
  pull-requests:write, id-token:write`. `anthropics/claude-code-action@v1` with
  `anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}`, a review `prompt`, and `claude_args`
  allow-listing only `gh pr comment` / inline-comment / `gh pr diff|view` tools. Comment-only,
  never a required check.
  - **Secret handling (honest):** GitHub Actions does **not** allow `secrets` in a job-level
    `if:` (secrets aren't available there), so the workflow can't cleanly self-skip when the key
    is missing. Until `ANTHROPIC_API_KEY` is added, the `claude-review` check simply **fails
    (red X) but does not block merge** (it's not a required check). Once the secret exists it
    works. To reduce noise before the secret is added, gate the job on a repo **variable**
    (`if: vars.ENABLE_CLAUDE_REVIEW == 'true'`) — a variable *is* allowed in `if:` — so the job
    is skipped-green until the operator flips the variable and adds the secret.
  - **Fork-PR limitation (deliberate):** GitHub does not expose secrets to workflows triggered by
    PRs **from forks** (external contributors). So automatic Claude review runs on internal-branch
    PRs but **not** fork PRs. We deliberately do **not** use `pull_request_target` to work around
    this — it would run untrusted PR code with secret access, which is unacceptable for a security
    repo. Fork PRs get the other gates (ci/secret-scan/semgrep run without needing secrets) and a
    maintainer can review manually.
- **dependabot.yml** — two updates, weekly: `package-ecosystem: uv` (dir `/`) and
  `package-ecosystem: github-actions` (dir `/`).

## Testing / verification (different from code)

Workflows can't be unit-tested locally. Verification = **push the branch, open the PR, observe
the checks**:
- Expect **green:** ci, secret-scan, semgrep, links.
- Expect **skipped:** codeql (private).
- Expect **pending/failing until the secret is added:** claude-review (operator adds
  `ANTHROPIC_API_KEY`).
Report the live check results after pushing — that IS the test. A YAML-lint / `actionlint` pass
locally (if available) is a cheap pre-check before pushing.

## Docs

- Brief `docs/user-guide/` or README note: "CI runs test+lint+secret+SAST on every PR; live-model
  evals and live-platform smokes are NOT in CI (run locally)." Update CLAUDE.md's Development
  Workflow / Testing section to mention the CI gates.
- README status badge(s) optional (defer until green).

## Out of scope (YAGNI / follow-up)

- **mypy as a hard gate** — needs the 53 strict errors cleaned first. Follow-up.
- **Publishing / release automation** (PyPI, tags) — not needed pre-public.
- **CodeQL activation** — happens automatically when the repo goes public; nothing more to build.
- No changes to `core/`, servers, tests, or tool code — this is CI config only.

## Files touched

| File | Change |
|---|---|
| `.github/workflows/ci.yml` | new — test + lint gate, mypy informational |
| `.github/workflows/secret-scan.yml` | new — gitleaks |
| `.github/workflows/semgrep.yml` | new — semgrep SAST |
| `.github/workflows/codeql.yml` | new — CodeQL, public-gated |
| `.github/workflows/deps.yml` | new — pip-audit, non-blocking |
| `.github/workflows/links.yml` | new — lychee link check |
| `.github/workflows/claude-review.yml` | new — Claude comment-only PR review |
| `.github/dependabot.yml` | new — uv + github-actions updates |
| `CLAUDE.md` / user-guide | note the CI gates + that live tests stay local |
