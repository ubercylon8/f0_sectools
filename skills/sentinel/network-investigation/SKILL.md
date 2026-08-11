---
name: network-investigation
description: Hunt an indicator across firewall, DNS and web telemetry
version: 1.0.0
metadata:
  hermes:
    tags: [security, sentinel, network, hunt, investigation]
    category: security
---

# Sentinel Network Investigation

## When to Use

When investigating an indicator — a domain, URL, IP or port — against
perimeter and egress telemetry: "did anyone reach this C2?", "what did the
firewall block from this host?", "is anyone using a personal VPN?". This is the
network complement to endpoint investigation.

## Procedure

Base tool names: `list_data_sources`, `hunt_firewall`, `hunt_dns_web`,
`search_office_activity`.

1. If you do not know what telemetry exists, call `list_data_sources` first.
2. Route the indicator by TYPE — this is the single most important decision
   in this skill:
   - **Domain or URL** → `hunt_dns_web` (`surface="dns"` for resolutions,
     `surface="web"` for fetches and downloads).
   - **IP address or port** → `hunt_firewall`.
   - **Never send a domain to `hunt_firewall`.** The firewall (CEF) table
     carries essentially no URL data — on a validated workspace, well under
     1% of rows had anything in a URL field. A domain query against it comes
     back empty, and reporting that as "no activity for this domain" would be
     wrong: it means the wrong table was asked, not that nothing happened.
3. Start with `action="blocked"` to see what controls already caught, then
   `action="allowed"` to find what got through. What was allowed is usually the
   more urgent half.
4. For a user rather than an address, use `surface="vpn"` for remote-access
   sessions, or `search_office_activity` for what they touched in M365.
   `search_office_activity` reads the same Microsoft 365 audit data as
   Purview's `search_audit_log` but through Log Analytics — it answers in
   under a second where Purview's asynchronous search takes 5-15 minutes.
   Prefer it here; fall back to Purview only when there is no Sentinel
   workspace, or for audit history older than the workspace's retention.
5. Correlate: a blocked DNS request plus an allowed firewall session to the
   same infrastructure means the DNS control worked and the IP path did not.

## Pitfalls

- **Without an indicator these tools return aggregates, not events.** That is
  deliberate — the firewall table is very large. Supply an indicator to see
  individual rows.
- **`hours` is capped at the workspace retention.** Asking for 90 days on a
  30-day workspace silently means 30; do not present it as 90.
- **Umbrella categories are a JSON list in one field.** Treat category matches
  as substring matches, not exact ones.
- Firewall data is Sentinel-only. For endpoint process/network telemetry use
  the Defender or LimaCharlie tools instead.
- **"No rows" and "no table" are different findings.** If `hunt_firewall` or
  `hunt_dns_web` returns a posture finding saying the table is absent, that is
  a visibility gap — report it as one, never as "checked, nothing suspicious".

## Verification

Every claim names the tool, the indicator, and the window. If a tool returned a
posture finding saying the table is absent, report that — never substitute a
different data source silently.
