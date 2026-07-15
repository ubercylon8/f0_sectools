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
   with a small `hours_back` window. Do NOT hand-write raw LCQL for host scoping —
   the `hostname` arg builds a safe selector for you. (Advanced/custom only: a raw
   `lcql` override exists; see `references/lcql-starters.md` in the threat-hunt skill.)
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
- Busy hosts return large result sets — narrow the window and use a filter.
- Hostnames must match what LimaCharlie has; if `get_sensor` finds nothing,
  confirm the name with `list_sensors`.

## Verification

The sensor's status comes from `get_sensor`/`list_sensors`; reported activity
corresponds to actual `query_telemetry` rows.
