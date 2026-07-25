# Read-Tool Staleness & Bounding Audit

**Date:** 2026-07-25 · **Status:** all findings fixed (Tier 1 in PR #74; tiers 2–4 follow-up) · **Trigger:** the Entra
risky-users staleness bug ([PR #73](https://github.com/ubercylon8/f0_sectools/pull/73))

The Entra fix exposed a defect *class*, not a one-off: a tool whose name promises
"what is happening now" issues a query that does not say so, and the caller cannot
tell an empty answer from an unasked question. This audit checks every read tool
across the 8 servers for the same shape.

## The four questions asked of each tool

1. **Filter placement** — is the caller's filter pushed server-side, or applied to
   an already-bounded page? (Client-side filtering *after* bounding under-reports.)
2. **Lifecycle state** — can already-handled records (resolved, dismissed,
   remediated) come back as if current?
3. **Ordering** — when the API returns more than one page, is the returned page the
   *relevant* one, or an arbitrary one?
4. **Truncation disclosure** — when results are cut, does the caller learn it?

## Findings

### Tier 1 — Defender `list_incidents` / `list_alerts` (4 defects, all reproduced offline)

All four are demonstrable without touching a tenant; the reproduction shapes its
mocked responses exactly as Microsoft documents them.

| # | Defect | Evidence |
|---|---|---|
| **D1** | **Severity filter runs after the page is bounded.** `$top=limit` fetches an arbitrary page, then `severity_min` is applied in Python. | A tenant whose first 25 alerts are low/resolved and whose 26th is a high/new ransomware alert: `list_alerts(severity_min="high")` returns **zero alerts** — only a "Showing 0; more results available" note. |
| **D2** | **No status filter.** Resolved/redirected incidents and resolved alerts are returned as current. This is the Entra bug verbatim. | `list_incidents(severity_min="low")` returned **24/25 already-resolved** incidents. |
| **D3** | **`alerts` is never `$expand`-ed.** `/security/incidents` does not return the `alerts` collection unless `$expand=alerts` is requested ([docs, Example 1](https://learn.microsoft.com/graph/api/security-list-incidents?view=graph-rest-1.0)). | Every incident reports `alerts: 0`. The "high severity + >3 correlated alerts → critical" escalation rule **can never fire**. The existing unit test passes only because its fixture hand-feeds an `alerts` array the real API does not send. |
| **D4** | **Two advertised enum values are absent from the lookup table.** The server advertises `Literal["info","low","medium","high","critical"]`; `_meets()` resolves the floor through `_SEV`, which has no `info` and no `critical` key, so both fall back to `medium`. | `severity_min="info"` keeps `[medium, high, critical]` — silently drops what was asked for. `severity_min="critical"` keeps `[medium, high, critical]` — silently returns far more than asked for. |

**What the Graph API actually supports** (authoritative, checked against Microsoft Learn):

- `/security/incidents` — `$filter` on **severity** and **status** (also assignedTo,
  classification, createdDateTime, determination, lastUpdateDateTime); `$expand` supported.
  **`$orderby` is not supported**, but the docs state the collection is returned
  most-recent-first by default.
- `/security/alerts_v2` — `$filter` on **severity**, **status**, serviceSource,
  createdDateTime, lastUpdateDateTime, assignedTo, classification, determination.
  **`$orderby` is not supported.**

So the remedy here is server-side `$filter` (+ `$expand=alerts`), **not** `$orderby` —
the opposite of the Entra fix, which needed `$orderby`. Worth stating plainly because
the initial hypothesis was "missing `$orderby`" and the docs disproved it.

> **Status: all tiers below are now fixed.** Tier 1 shipped in
> [PR #74](https://github.com/ubercylon8/f0_sectools/pull/74); tiers 2–4 in the
> follow-up branch. See *Follow-up verification* at the end for what the live probes
> overturned — the truncation work found a second `accepted ≠ honoured` trap, this
> time in a field's *value* rather than a parameter's effect.

### Tier 2 — Silent truncation (no "more available" note)

The tool cuts results and says nothing, so `25 devices` reads as *the tenant has 25
devices*. `core/paging.more_available_finding` exists for exactly this and is used by
Defender, Entra and Tenable's `list_vulnerability_assets` — but not by:

- **Intune** — `list_managed_devices`, `list_compliance_policies`,
  `list_configuration_profiles`, `list_stale_devices` (none check `@odata.nextLink`)
- **Tenable** — `list_top_vulnerabilities`, `list_assets`, `get_asset_vulnerabilities`,
  `list_scans`
- **LimaCharlie** — `list_dr_rules`, `list_detections`
- **ProjectAchilles** — `list_risk_acceptances`, `list_agents`

Severity varies: on the Tenable tools the *filter* runs before the bound, so the top-N
is genuinely the top-N and only the "how many more" context is missing. On Intune's
device list the page itself is arbitrary.

### Tier 3 — Purview `_fetch_alerts`

- **No status filter** — a resolved DLP alert inside the window counts as current, in
  both `get_dlp_summary`'s headline and `list_dlp_alerts`' rows.
- `_FETCH_CAP = 100` takes an arbitrary 100 when the window holds more. The summary is
  honest about this ("showing counts for first 100"); the list is less so —
  `_more_note(limit, len(kept))` reports the count *within the fetched page*, not the
  true total.

Mitigating: the time window **is** pushed server-side, so this cannot surface a
five-year-old alert the way Entra did.

### Tier 4 — Tenable `list_scans`

Fetches all scans and takes the first `limit` with no ordering, though
`last_modification_date` is available. "Recent scans" is not what it returns.

### Clean — no change needed

- **ProjectAchilles `list_test_executions`** — the reference implementation: explicit
  `sortField`/`sortOrder=desc`, server-side window, and it reads `pagination.totalItems`
  to detect truncation rather than guessing.
- **Intune `list_managed_devices` / `list_stale_devices`** — server-side `$filter`, with
  a code comment recording that `managedDevices` *silently ignores* `$orderby` (confirmed
  live). That comment is the reason this audit does not trust documentation alone.
- **Tenable `list_top_vulnerabilities` / `get_asset_vulnerabilities`** — filter and sort
  before bounding: the correct ordering of operations.
- **ProjectAchilles `list_risk_acceptances` / `list_agents`** — server-side status params.
- **Entra** — fixed in PR #73.

## Live verification (operator-authorized, read-only, 2026-07-25)

Documentation is necessary but not sufficient: Intune's `managedDevices` accepts
`$orderby` and silently ignores it. Every query shape below was exercised against the
real tenant with read-only GETs. Verdicts are structural only — no tenant identifiers.

| Query shape | `/security/incidents` | `/security/alerts_v2` |
|---|---|---|
| `$filter` on `severity` | honoured | honoured |
| `$filter` on `status` | honoured | honoured |
| OR-chain across severities | honoured | honoured |
| severity OR-chain **and** status | honoured | honoured |
| `$count=true` **with** `$filter` | honoured — returns the true *filtered* total | honoured |
| `$orderby=createdDateTime desc` / `asc` | **honoured** | **honoured** |
| `$orderby=lastUpdateDateTime desc` | accepted, **silently ignored** | accepted, **silently ignored** |
| `$orderby=severity desc` | HTTP 400 | HTTP 400 |
| **No** `$orderby` | **not newest-first** | **not newest-first** |
| `$expand=alerts` | honoured | n/a |
| `$expand=alerts($select=…)` | honoured | n/a |

**Correction to the documentation-based reading above.** Microsoft's docs list neither
endpoint as supporting `$orderby`, and this audit's first draft concluded ordering was
unavailable. It is not: `$orderby=createdDateTime` is honoured in both directions on both
endpoints. Only `lastUpdateDateTime` exhibits the silent-ignore trap, and `severity`
errors outright. Meanwhile the docs' claim that incidents come back "most recent first"
by default is **false on this tenant** — the unordered page is not monotonic. So ordering
must be requested explicitly, and only on `createdDateTime`.

### Status enums differ between the two endpoints

- **incidents** — `active`, `resolved`, `redirected` (and `inProgress`, valid but unused
  here). `redirected` means merged into another incident: already handled.
- **alerts_v2** — `new`, `inProgress`, `resolved`, `unknown`. **`active` is not valid**
  and returns HTTP 400; `dismissed` likewise. A shared status constant across the two
  tools would break one of them.

### `$expand=alerts` is unaffordable bare, affordable with a nested `$select`

| Query | Payload |
|---|---|
| 5 active incidents, no `$expand` | 4.0 KB |
| 5 active incidents, `$expand=alerts` | **75.5 KB** |
| 5 active incidents, `$expand=alerts($select=id,severity,status,mitreTechniques)` | **4.9 KB** |

Bare `$expand` costs ~15 KB per incident — far past a small model's output budget
(Critical Rule 5). The nested `$select` gets the correlated-alert count for +0.9 KB.

### Signal-to-noise on the live tenant

| | Total in collection | Genuinely unresolved |
|---|---|---|
| Incidents | 2,172 | **5** |
| Alerts | 3,151 | **6** |

Of the tenant's 3,151 alerts, six are unresolved, and none are high or medium
(`status in (new, inProgress) and severity in (high, medium)` → `$count` = 0). The current
tools return an arbitrary 25-row page from those collections; in the sampled run every
returned alert was already `resolved`. The tools are, in practice, showing roughly zero
actionable rows on a tenant that has a small but real set of them.

### Design consequences

1. Push `severity` **and** `status` into `$filter`; never filter a bounded page.
2. Request `$orderby=createdDateTime desc` explicitly — the default order is not recency.
3. Use `$count=true` for an honest "showing M of N" instead of inferring from `nextLink`.
4. Use `$expand=alerts($select=…)` so the critical-escalation rule works without a 15×
   payload blow-up.
5. Keep the two status vocabularies separate — one shared constant cannot serve both.
6. `severity_min` needs a real mapping: Graph has no `critical` (ours is derived from the
   escalation rule, so it must stay a client-side refinement of `high`), and Graph's
   `informational`/`unknown` both mean our `info` (so `severity_min="info"` is *no*
   severity filter rather than a broken one).

---

## Follow-up verification (operator-authorized, read-only, 2026-07-25)

Tiers 2–4 were probed the same way as Tier 1, and the probes were again load-bearing.

### Purview — the status filter was a live reporting bug

| | Result |
|---|---|
| DLP alerts in the default 168h window | **6** |
| …of which unresolved | **0** — every one was already `resolved` |

The headline read "6 DLP alerts", and that headline feeds the **CISO report's
data-risk tile**, so the shipped report overstated current data risk. `status ne
'resolved'` is honoured on `alerts_v2`, and `@odata.count` there *is* the true
filtered total, so the summary can now report what matched rather than what it
happened to fetch.

A second-order point drove the guidance change: "nothing happened" and "everything
was handled" both render as `0`, but they mean opposite things — the first suggests
DLP may not be deployed, the second proves it is working. The zero-case guidance now
tells the operator to re-run with `state="all"` to tell them apart.

### Intune — `@odata.count` is a trap on two of three endpoints

Probed with `$top=3` against a **1,507-device** tenant:

| Endpoint | `$top=N` alone | `$top=N&$count=true` | Reliable signal |
|---|---|---|---|
| `managedDevices` | `count=3` — **echoes the page** | `count=1507` but **zero rows** | `@odata.nextLink` |
| `deviceConfigurations` | no count | `count=2` of 28 — **echoes the page** | `@odata.nextLink` |
| `deviceCompliancePolicies` | no count, never a nextLink | `count=9` — **the true total** | `$count=true` |

The first implementation trusted `@odata.count` uniformly and a 5-of-1,507 page
reported no truncation at all — the fix reproduced the very bug it was written to
close. This is the Tier-1 lesson one level deeper: it is not enough to ask whether a
parameter is *honoured*; a field that is present and well-typed can still not mean
what its name implies. So the "trust the count" decision is per call site.

### Tenable — the API's own total contradicts the API's own listing

| Query | assets returned | `total` field |
|---|---|---|
| `?limit=10` | 10 | **580** |
| unbounded | 314 | **314** |

Quoting `total` would have produced "Showing 10 of 580" from a tool whose full
listing returns 314. `list_assets` therefore reports a full page as "more available"
rather than quoting a number it cannot stand behind, and uses an exact count only on
the hostname path, where it fetches the whole workbench and filters locally.

`/scans` was confirmed unordered (141 scans, not newest-first) and only **37 of 141**
carry `last_modification_date`; those without one now sort last rather than being
dropped.

### ProjectAchilles — two endpoints, two shapes

`/agent/admin/agents` reports its total under `data.total` (22); `/risk-acceptances`
reports it at the **top level** (`total`). Both are honest totals, but a single
extraction path would have silently missed one.

### Result

Every bounded call now discloses what it withheld, and every complete call stays
silent — verified live across all four platforms.
