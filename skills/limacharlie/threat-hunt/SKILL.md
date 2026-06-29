---
name: limacharlie-threat-hunt
description: Run guided LimaCharlie LCQL telemetry hunts
version: 1.0.0
metadata:
  hermes:
    tags: [security, limacharlie, threat-hunting, lcql, edr]
    category: security
---

# Guided LimaCharlie Threat Hunt (LCQL)

## When to Use

The user wants to hunt across the endpoint fleet — e.g. "hunt for PowerShell
spawning", "any connections to this domain", "look for new services". Uses
LimaCharlie Query Language (LCQL) over endpoint telemetry. Uses the
**f0_sectools LimaCharlie** MCP server (read-only).

## Tools

Base tool name (runtime may prefix — see the LimaCharlie server README):
`query_telemetry`. Read-only; runs a bounded endpoint-telemetry hunt.

## Procedure

1. State the **hypothesis** in one sentence (what behaviour, on what platform,
   why it matters).
2. Pick a `hunt` **preset** that matches — `new_processes`,
   `powershell_activity`, `dns_requests`, or `network_connections` — and a bounded
   `hours_back` / `limit`. (For a custom hunt, pass a raw `lcql` query instead;
   see `references/lcql-starters.md` for the shape and examples.)
3. Call `query_telemetry` with the chosen preset (or `lcql`).
4. Review the returned rows; note what supports or refutes the hypothesis.
5. Refine once or twice (narrow the window, add a filter, change event type),
   then summarise: hypothesis, what you ran, what you found, and the TTPs.

## Discipline (small local models)

- Build **one** query at a time; inspect results before writing the next.
- Always bound results (`limit`) and keep the window tight; never request
  unbounded telemetry.
- Report only the rows the tool returned. Do not invent hosts or values.
- If the tool returns a `posture` finding (permission / auth / rate-limited),
  relay it and stop.

## Pitfalls

- LCQL field and event-type names must be exact — prefer the vetted starters
  over free-handing a query for a small model.
- Telemetry retention varies by organization; very old activity may be absent.
- Broad selectors (`*`) with no filter are slow and noisy — start narrow.

## Verification

The summary's findings correspond to actual returned rows. Zero rows means "no
matching activity in the window", not a fabricated result.
