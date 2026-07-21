---
name: investigate-lc-endpoint
description: Investigate a LimaCharlie endpoint and its activity
version: 1.0.0
metadata:
  hermes:
    tags: [security, limacharlie, edr, endpoint, investigation]
    category: security
---

# Investigate a LimaCharlie Endpoint

## When to Use

The user wants to look into a specific endpoint — e.g. "investigate web-01",
"what's running on that host", "is this sensor online and what has it done".
Uses the **f0_sectools LimaCharlie** MCP server (read-only).

## Tools

Base tool names (runtime may prefix — see the LimaCharlie server README):
`get_sensor`, `list_sensors`, `query_telemetry`. Read-only.

## Procedure

1. Call `get_sensor` with the hostname. Note **online status**, **platform**,
   and the sensor id. If nothing is found, call `list_sensors` to locate the
   right hostname.
2. Query that host's recent activity with `query_telemetry` — pass the
   **`hostname` argument** to scope to that one sensor and pick a `hunt` preset
   (`new_processes`, `powershell_activity`, `dns_requests`, `network_connections`)
   with a small `hours_back` window (fractional is fine: 0.25 = 15 minutes). Do NOT
   hand-write raw LCQL for host scoping — the `hostname` arg builds a safe selector.
   For a **domain** question ("does host X connect to `microsoft.com`"), pass the
   **`domain` argument** — it routes to DNS lookups filtered by that domain. Do NOT
   use `network_connections` for domain questions: those events carry IPs, not domains.
   (Advanced/custom only: a raw `lcql` override exists; see
   `references/lcql-starters.md` in the threat-hunt skill.)
3. Review the returned findings: the leading finding gives the total event count;
   each following finding is one event (process/command line, domain, etc.).
4. Summarize: sensor status, what the telemetry shows, and a recommended next
   step.

## Discipline (small local models)

- One tool at a time; inspect results before the next query.
- Bound every LCQL query and report only returned rows — never invent activity.
- Relay any `posture` finding (permission / auth / rate-limited) and stop.

## Pitfalls

- An **offline** sensor has no live data, but historical telemetry may still be
  queryable (retention varies by org).
- A sensor tagged **`lc:sleeper` is dormant**: it stays enrolled and online but
  collects **no telemetry by design**. A zero-event result on such a host is
  expected, not suspicious — `query_telemetry` and `get_sensor` say so; report
  the dormant state instead of guessing at other explanations.
- Busy hosts return large result sets — narrow the window and use a filter.
- Hostnames are fine as short names — `query_telemetry`/`get_sensor` resolve
  them to the stored (often FQDN) hostname; if no sensor matches, confirm the
  name with `list_sensors`.

## Verification

The sensor's status comes from `get_sensor`/`list_sensors`; reported activity
corresponds to actual `query_telemetry` rows.
