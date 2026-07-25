# Per-Persona Report Gathering — Design

**Date:** 2026-07-25 · **Status:** approved-pending-review · **Branch:** `feat/report-persona-gathering`

Make the three operational persona reports gather **their own** data instead of
the CISO six-pillar rollup. Today every persona gathers the same six pillars, so
a detection-engineer report renders Secure Score as a "detection finding" and
carries no MITRE at all — the operational reports are the CISO data wearing an
operational layout.

## Problem

Confirmed by generating a real detection-engineer report; its entire Findings
section was two rows:

```
[LOW]  Microsoft Secure Score: 1633/1816 (90%) — defender
[INFO] Org '…': 1252 sensors (1178 dormant), 0 detections (24h) — limacharlie
```

Two compounding causes:

1. **`gather()` ignores the persona.** `scripts/report_gather.py` iterates a flat
   `_PILLAR_FACTORIES` (the six CISO pillars) for every persona. Its own comment
   says so: `# v1: all personas gather the six pillars … extend GATHER_MAP later`.
2. **Source-based buckets silently drop findings.** Operational `SECTION_MAPS`
   point at `FindingGroup.detections` / `telemetry`, and `sections.group_findings`
   buckets by `finding.source` — so the tenable/intune/purview/projectachilles
   pillars never reach the detection-engineer's section at all.

The original report-generation design promised per-persona gathering
(`docs/superpowers/specs/2026-07-24-report-generation-design.md`): *"Detection
engineer: Defender incidents+MITRE, LimaCharlie D&R coverage, PA weak
techniques"*. This spec delivers that. The user-guide's claim that operational
personas get "evidence and MITRE technique references" becomes true only once
this lands.

## Design

### 1. `GATHER_MAP` replaces `_PILLAR_FACTORIES`

`scripts/report_gather.py` currently holds one flat dict of six pillar factories.
Replace it with a per-persona map:

```python
GATHER_MAP: dict[str, dict[str, Callable[[int], Awaitable[list[Finding]]]]]
```

keyed by the normalized persona (`ciso`, `detection_engineer`, `threat_hunter`,
`security_engineer`), each value being that persona's `{group label: factory}`.
`gather(persona, window_hours)` normalizes the persona (hyphen→underscore),
looks up its map, and runs the factories concurrently exactly as today. An
unknown persona raises `ValueError` (fail loud, consistent with `build_report`).

Everything downstream is unchanged in shape: each group still degrades
gracefully, and `assessed` / `not_assessed` now carry the persona's group labels
rather than the six pillar names. The CISO map is today's six pillars verbatim,
so the CISO report is bit-for-bit unaffected.

### 2. What each persona gathers

Tools chosen from those that exist today; every list call is bounded so the
report stays readable.

| Persona | Group label → tool |
|---|---|
| **ciso** | *unchanged* — Config hardening, Attack validation, Vulnerability exposure, Device compliance, Data risk, Endpoint coverage |
| **detection_engineer** | Alerts (MITRE) → defender `list_alerts(severity_min="medium", limit=15)` · Incidents → defender `list_incidents(severity_min="medium", limit=10)` · Detection rules → limacharlie `list_dr_rules` · Endpoint detections → limacharlie `list_detections(hours_back=window, limit=15)` · Weak techniques → projectachilles `get_weak_techniques(limit=10)` |
| **threat_hunter** | Incidents → defender `list_incidents(severity_min="medium", limit=10)` · Alerts (MITRE) → defender `list_alerts(severity_min="medium", limit=15)` · Endpoint detections → limacharlie `list_detections(hours_back=window, limit=15)` · Endpoint coverage → limacharlie `get_org_overview` |
| **security_engineer** | Config hardening → defender `get_secure_score` · Conditional access → entra `list_conditional_access_policies` · Privileged roles → entra `list_privileged_role_assignments(limit=10)` · Risky users → entra `list_risky_users(limit=10)` · Device compliance → intune `get_compliance_summary` · Stale devices → intune `list_stale_devices(limit=10)` · Vulnerability exposure → tenable `get_vulnerability_summary` · Top vulnerabilities → tenable `list_top_vulnerabilities(limit=10)` |

Entra joins as a seventh source (security engineer only), constructed exactly
like the other Graph platforms: `PlatformConfig.from_env("ENTRA")` +
`GraphClient`, mirroring `scripts/live_smoke_entra.py`.

**Deliberately excluded:** defender `hunt` and limacharlie `query_telemetry`.
Both require an arbitrary category (and, for network/process hunts, an
indicator); picking one for an unattended report would fabricate a hypothesis.
Hunting stays interactive — the report gives the hunter incidents, MITRE-bearing
alerts, and endpoint detections to start *from*.

### 3. Operational sections render everything gathered

Because the gather is now persona-scoped, the section no longer needs to filter
by source — filtering is what dropped findings. Change the three operational
entries in `sections.SECTION_MAPS` from `FindingGroup.detections` / `telemetry`
to `FindingGroup.all`, and simplify `group_findings` to the buckets that are
actually consumed: `all` (real findings), `top_risks` (real findings), `posture`
(posture-typed). Delete the now-dead `detections` / `telemetry` / `exposure` /
`identity` / `compliance` members of `FindingGroup` and their bucketing loop.

### 4. Metric tiles stay CISO-only

Operational groups return *lists* (12 incidents), not one headline number, so a
tile would be meaningless. `SECTION_MAPS` already gives `metric_grid` to the
CISO only; `gather` therefore computes `pillar_metrics` only for the CISO and
leaves it empty for operational personas (an empty metric list is already
handled — those personas have no metric section to render it in).

## Components / files

- `scripts/report_gather.py` — `GATHER_MAP` (per-persona), the new operational
  factories (defender alerts/incidents, limacharlie rules/detections/overview,
  PA weak techniques, entra CA/roles/risky users, intune compliance/stale,
  tenable summary/top vulns), persona-scoped `gather`, CISO-only
  `pillar_metrics`.
- `core/f0_sectools_core/reports/sections.py` — operational `SECTION_MAPS` →
  `FindingGroup.all`; `FindingGroup` and `group_findings` simplified.
- `scripts/tests/test_gen_report.py`, `core/tests/test_reports_sections.py` —
  tests below.
- `docs/user-guide/workflows.md` — heading "Markdown + PDF" → "Markdown, HTML +
  PDF"; describe what each persona's report actually contains now.

## Error handling & guarantees

- **Graceful partial, unchanged** — a factory that raises degrades to a
  `not configured` posture finding for that group; the report still generates and
  names the dark group under "not assessed".
- **Bounded** — every list call carries an explicit limit (10–15).
- **Redaction unchanged** — `_run_pillar` still applies `redact_finding` to every
  gathered finding before it reaches the report.
- **Platform-free core** — all platform wiring stays in `scripts/`;
  `core/reports/` gains no imports.
- **Concurrency** — the persona's factories still run under one `asyncio.gather`.

## Testing

Layer A (offline, CI — factories monkeypatched, no live platform):
- `GATHER_MAP` has an entry for all four personas; an unknown persona raises.
- Each persona's `gather` runs *its own* group labels (e.g. detection_engineer
  yields "Alerts (MITRE)"/"Weak techniques", not "Data risk").
- A raising factory degrades that group to `not_assessed` and the rest still
  return.
- `pillar_metrics` is populated for `ciso` and empty for an operational persona.
- **Regression for the drop bug:** an operational report built from findings
  across several sources renders *all* of them (previously the source buckets
  dropped any source not in the persona's bucket).
- Existing suite stays green; the CISO golden is unchanged (its map is verbatim).

Layer B (operator-gated): generate a live detection-engineer report and confirm
it contains real alerts/detections with MITRE references rather than Secure
Score.

## Out of scope

- Charts/gauges; interactive hunts (`hunt`, `query_telemetry`) in reports.
- Per-persona *narrative* templates (the one skill already covers all personas).
- New tools on any server — this wires existing ones only.
- Changing the findings schema, the chat persona renderers, or the report engine's
  rendering (the tile/CSS work is already done on this branch).
