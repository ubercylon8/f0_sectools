# Guided Defender Hunt (`hunt`) — Design Spec

**Date:** 2026-07-14
**Status:** Approved for planning
**Type:** New Defender tool + small refactor (touches `defender` server only)
**Origin:** pi live-run — Qwen3.5-9B burned ~12 `run_hunting_query` calls guessing DeviceNetworkEvents field names (`Destination_Fqdn`, `DestinationIP`, …; the correct field is `RemoteUrl`) and gave up. Raw KQL is the small-model anti-pattern CLAUDE.md explicitly warns against ("free-text args the model must construct without a guided, validated helper").

## Goal

Give small local models a **hard guardrail** for Defender advanced hunting: a guided tool where the model passes a *category + indicator*, and the **server builds the vetted KQL with correct field names**. Keep raw `run_hunting_query` for power use, but make its description schema-aware.

## Design decisions (approved)

- **One enum tool** `hunt(category, indicator, time_window_hours)` — not several dedicated tools (keeps Defender ≤8: 6→7).
- **Four categories:** `network`, `process`, `logon`, `email` — the four tables our `skills/defender/threat-hunt/references/kql-starters.md` already templates.
- Keep `run_hunting_query`; enrich its description with per-table field hints (the "bit of B").

## Verified facts (ground truth)

- Defender has **6 tools** (`get_secure_score`, `list_incidents`, `list_alerts`, `run_hunting_query`, gated `isolate_host`/`release_host`).
- `run_hunting_query(gc, kql)` POSTs `{"Query": kql}` to `/security/runHuntingQuery`, reads `resp.get("results")`, renders the first `_MAX_HUNT_ROWS` as `row_i` evidence on one `hunt_result` finding, and maps a `GraphError` via `map_graph_error(..., "ThreatHunting.Read.All", ...)`.
- Correct Defender advanced-hunting fields (from our own `kql-starters.md`, the source of truth this tool encodes):
  - **network:** `DeviceNetworkEvents` — `Timestamp`, `RemoteUrl`, `RemoteIP`, `RemotePort`, `InitiatingProcessFileName`, `ActionType`.
  - **process:** `DeviceProcessEvents` — `Timestamp`, `DeviceName`, `AccountName`, `FileName`, `ProcessCommandLine`.
  - **logon:** `DeviceLogonEvents` — `Timestamp`, `ActionType == "LogonFailed"`, `AccountName`, `DeviceName`.
  - **email:** `EmailEvents` — `Timestamp`, `SenderFromAddress`, `RecipientEmailAddress`, `Subject`, `ThreatTypes`.
- **⚠️ LIVE-VALIDATION unknown:** the tenant's successful query returned `TimeGenerated` (Sentinel/Azure convention), but Defender M365 advanced hunting device tables use `Timestamp`. The templates use `Timestamp` (documented Defender field); confirm against the operator's tenant and fix-forward if it needs `TimeGenerated`.

## Component design

### C1 — `hunt` tool (`servers/defender-mcp/.../tools.py`)

```python
async def hunt(gc, category: str, indicator: str = "", time_window_hours: int = 24) -> list[Finding]:
    ...
```

**Behaviour:**
1. **Validate `category`** ∈ {network, process, logon, email} → else a graceful posture finding: `"Unknown hunt category '<x>'. Use: network, process, logon, email."` (no query built).
2. **Indicator rules:**
   - `network`, `process`: indicator **required**. Empty → graceful finding: `"The <category> hunt needs an indicator (network: a domain or IP; process: a name or command-line fragment)."`
   - `logon`, `email`: indicator **optional** (adds a filter line when present).
3. **Sanitize the indicator** (it is interpolated into a KQL string literal — injection guard): validate against `^[A-Za-z0-9._:@/\\-]{1,120}$` (covers domains, IPs, process names/paths, emails). Fail → graceful finding: `"Indicator contains unsupported characters; use a plain domain, IP, process name, or account."` No query is built on failure. (Whitelist-reject, never strip-and-run.)
4. **Clamp `time_window_hours`** to `[1, 720]` (30-day hunting retention), default 24.
5. **Build the KQL** from the category template (below), substituting the sanitized indicator and window, with a fixed `| take <_MAX_HUNT_ROWS>` bound.
6. **Execute + render** via a shared helper `_execute_hunt(gc, kql)` extracted from `run_hunting_query` (same POST, same row rendering, same error mapping) — DRY.

**Templates** (H = window hours, IND = sanitized indicator, N = `_MAX_HUNT_ROWS`):

- network:
  ```kql
  DeviceNetworkEvents
  | where Timestamp > ago(<H>h)
  | where RemoteUrl contains "<IND>" or RemoteIP == "<IND>"
  | project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, ActionType
  | take <N>
  ```
- process:
  ```kql
  DeviceProcessEvents
  | where Timestamp > ago(<H>h)
  | where FileName has "<IND>" or ProcessCommandLine contains "<IND>"
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
  | take <N>
  ```
- logon (indicator optional — the `AccountName` line is added only when IND is non-empty):
  ```kql
  DeviceLogonEvents
  | where Timestamp > ago(<H>h)
  | where ActionType == "LogonFailed"
  [| where AccountName has "<IND>"]
  | summarize Failures = count() by AccountName, DeviceName, bin(Timestamp, 1h)
  | where Failures > 10
  | take <N>
  ```
- email (indicator optional — the sender/subject line added only when IND is non-empty):
  ```kql
  EmailEvents
  | where Timestamp > ago(<H>h)
  | where ThreatTypes has "Phish" or ThreatTypes has "Malware"
  [| where SenderFromAddress has "<IND>" or Subject contains "<IND>"]
  | project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes
  | take <N>
  ```

### C2 — Refactor `run_hunting_query` → shared `_execute_hunt`

Extract the POST + row-render + error-map from `run_hunting_query` into `_execute_hunt(gc, kql) -> list[Finding]`; `run_hunting_query` becomes a thin wrapper (`return await _execute_hunt(gc, kql)`), and `hunt` calls it too. No behaviour change to `run_hunting_query`.

### C3 — Enrich `run_hunting_query` tool description (bit of B)

In `server.py`, extend the docstring with the **key fields** per table so raw-KQL use stops guessing:
> …Common tables & key fields: DeviceNetworkEvents (`Timestamp`, `RemoteUrl`, `RemoteIP`, `RemotePort`), DeviceProcessEvents (`Timestamp`, `DeviceName`, `FileName`, `ProcessCommandLine`, `AccountName`), DeviceLogonEvents (`Timestamp`, `ActionType`, `AccountName`, `DeviceName`), EmailEvents (`Timestamp`, `SenderFromAddress`, `Subject`, `ThreatTypes`). Prefer the `hunt` tool for common cases.

### C4 — Register `hunt` (`server.py`)

```python
@mcp.tool()
async def hunt(category: str, indicator: str = "", time_window_hours: int = 24) -> list[dict[str, Any]]:
    """Guided Microsoft Defender hunt — the server builds correct KQL, so you don't have to.

    category: network | process | logon | email.
    indicator: what to look for — a domain/IP (network), a process name or
    command-line fragment (process); optional for logon/email. Prefer this over
    run_hunting_query unless you need custom KQL.
    """
    ...
```

### C5 — Skill + reference

- `skills/defender/threat-hunt/SKILL.md` — make `hunt` the **primary** path (Procedure step 2: "call `hunt` with a category + indicator"); raw `run_hunting_query` + `kql-starters.md` become the fallback for custom queries. Keep `description` ≤60 chars.
- `kql-starters.md` stays as-is (the source of truth the tool encodes; now also the "custom query" reference).

## Testing

`servers/defender-mcp/tests/test_tools.py` (respx — capture the POSTed `Query` body):
- Each category builds the right table + fields + window + indicator (assert the POST body contains e.g. `DeviceNetworkEvents`, `RemoteUrl contains "evil.com"`, `ago(24h)`).
- `network`/`process` with empty indicator → graceful finding, **no POST made**.
- `logon`/`email` with no indicator → POST made, template without the optional filter line.
- Invalid indicator (`"evil\".io`) → graceful finding, **no POST**.
- `time_window_hours` clamp (e.g. 99999 → `ago(720h)`; 0 → `ago(1h)`).
- Unknown category → graceful finding, no POST.
- `run_hunting_query` still works (shared helper) — existing test stays green.
- 403 on `hunt` → posture finding via the shared error path.

## Live validation (operator-driven)

- Exercise on pi: *"check for network connections to projectachilles.io"* → `hunt(network, "projectachilles.io")`. Confirm rows return.
- The **`Timestamp` vs `TimeGenerated`** question is the one thing to confirm; if the tenant needs `TimeGenerated`, fix-forward the templates + `kql-starters.md` together.
- Add `hunt` to `scripts/live_smoke_defender.py` if one exists (else note it).

## Docs & counts

- Tool count **35 → 36** (34 read + 2 gated). Update *current-inventory* refs (README headline, `docs/user-guide/README.md` matrix Defender row → add "guided hunt", `CLAUDE.md`). **Do NOT change the scorecard "34"/eval counts** — `hunt` is pending its scorecard pass (note it, same guardrail as the Tenable tool).
- `CHANGELOG.md` `[Unreleased]` — add the `hunt` tool under Added.
- `evals/defender/tasks.yaml` — **keep** the existing `run_hunting_query` task (it represents the "custom KQL" path). **Add** guided-path tasks that must route to `hunt`: "check for network connections to evil.com" → `hunt {category: network}`; "hunt for PowerShell process launches" → `hunt {category: process}`; a logon and an email task. Add one explicit-KQL task ("run this hunting query: DeviceInfo | take 5") that must still route to `run_hunting_query`, to prove the two don't collide.

## Disambiguation (hunt vs run_hunting_query)

Two tools now cover hunting, so their descriptions must route cleanly (the #2.5 collision pattern):
- **`hunt`** — the default for natural-language hunts ("check for connections to X", "look for PowerShell", "any failed logons"). Description leads with "the server builds the KQL, so you don't have to."
- **`run_hunting_query`** — only when the user supplies/asks for **custom KQL**. Description says "for a custom KQL query you provide; for common hunts prefer `hunt`."
The eval's explicit-KQL task guards this boundary.

## Non-goals (YAGNI)

- Additional categories (DNS, file, registry, cloud) — v1 is the four templated tables; raw KQL covers the long tail.
- A KQL validator / `describe_table` tool — the guided tool + enriched description are enough now.
- Parsing/normalizing hunt rows into structured entities — keep the existing raw-row rendering.
- LimaCharlie LCQL guided hunting — separate effort (this is Defender/KQL only).

## Constraints

- Read-only; no gating/redaction/schema changes; every failure a finding, never an exception.
- Small-model-safe: flat scalar args, one short closed enum (`category`), descriptive names, bounded output. Defender stays ≤8 tools (→7).
- Indicator sanitization is mandatory (KQL injection guard) — whitelist-reject.
- Push is user-gated; the tool is live-validation-pending (esp. `Timestamp` vs `TimeGenerated`).
