# Glossary

Terms used throughout f0_sectools, defined once. Linked concepts point at the
document that owns them.

**agent persona** — One of four behavioural lenses (CISO, threat hunter,
detection engineer, security engineer) that shapes which skills/tools the agent
favours and how it frames a whole response. Delivered as Hermes
`agent.personalities`, opencode agent files, pi prompt templates, and modes in
the portable prompt. Distinct from a *persona renderer* (below).

**agentskills.io skill** — A portable playbook in the open `SKILL.md` standard
(YAML frontmatter + When to Use / Procedure / Pitfalls / Verification).
f0_sectools ships one set in `skills/`; runtimes load it unmodified —
never forked per runtime.

**audit trail** — The local JSONL log (`$F0_GATING_DIR/audit.log`) recording
every executed gated action: action, target, actor, method, and a hash
reference of the confirmation. Never shipped off-host. See the
[security model](../explanation/security-model.md#layer-3--the-audit-trail).

**callability** — Whether a real small model can reliably *drive* a tool:
select it for the right task and fill its arguments correctly. Measured by the
[eval harness](../../evals/README.md), reported in the
[scorecard](../../evals/SCORECARD.md). Distinct from code correctness.

**chat-confirm** — The opt-in, per-platform gating mode
(`<PLATFORM>_CONFIRM_MODE=chat`) where the operator's in-chat "approved" is the
confirmation. Convenient for supervised, reversible actions; **not
forge-resistant** and never permitted for destructive actions. See
[security model](../explanation/security-model.md#layer-2--human-confirmation-three-surfaces).

**composition test** — The eval's hard mode: every server's tools registered
at once (`--server all`). Measures whether tool routing survives a many-tool
registry.

**contract test** — An offline pytest against a fake platform client,
asserting schema shape, redaction (success *and* error paths), pagination
bounds, and gate refusal. Mandatory for every server; runs in CI.

**finding** — The normalized JSON object every tool returns; the single
output contract. See [the findings schema](../explanation/findings-schema.md).

**forge-resistant** — Property of a confirmation surface the model cannot
fabricate: the approval or token is issued out-of-band, never enters model
context, and is single-use, target-bound, and TTL'd. The watcher and token
surfaces are forge-resistant; chat-confirm is not.

**gated action / gated write** — Any tool that changes state on a live
platform (isolate host, run a validation test, cancel tasks). Disabled by
default; execution requires the platform write flag **and** a per-action human
confirmation, and is audited. Implemented once in `core/gating/`.

**intent finding** — What a gated tool returns on first call: a
`finding_type: "action"` finding describing exactly what it *would* do and to
which target, executing nothing. Confirmation happens after the intent.

**live-validated** — Status label for a server that has been run against a
real tenant via its smoke script (`scripts/live_smoke_<platform>.py`), with
field-name/shape mismatches fixed forward. Mocks encode assumptions; the live
API is truth.

**persona renderer** — A deterministic, model-free formatter in
`core/renderers/` that turns a finding into audience-shaped Markdown
(analyst / engineer / CISO / hunter / detection engineer). Shapes a *finding's
text*; the agent persona shapes *behaviour*. The two compose.

**posture finding** — A `finding_type: "posture"` finding: environment-level
statements (scores, coverage) and every graceful degradation — missing
permission, throttled, API unavailable, results truncated.

**redaction** — The mandatory pass (`core/redaction/`) that strips
secret-keyed values and token-shaped strings from every return path, replacing
them with `«redacted»`. Applied at the server boundary, including errors.

**skills-aware runtime** — An agent runtime that natively loads `SKILL.md`
skills (Hermes, Claude Code, pi, opencode). Non-skill UIs (LM Studio,
Open WebUI) use the portable system prompt in `prompts/` instead.

**smoke script** — `scripts/live_smoke_<platform>.py`: calls every one of a
server's tools once against the real platform and prints redacted findings.
The live-validation gate; never run in CI.

**thin server** — A per-platform MCP server that contains only the platform
client and tool definitions, importing everything cross-cutting (schema,
redaction, auth, paging, gating, renderers) from `core/`. See
[architecture](../explanation/architecture.md#the-server-pattern).

**watcher** — The default confirmation surface: the operator runs
`python scripts/confirm_action.py --watch` in their own terminal and approves
pending gated actions with a keypress. No token ever enters model context.

**write flag** — The per-platform environment variable
(`<PLATFORM>_ALLOW_WRITE=true`) that makes a platform's gated tools available
at all. One of the two keys; the confirmation is the other.
