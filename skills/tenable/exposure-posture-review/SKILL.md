---
name: review-exposure-posture
description: Review Tenable vulnerability exposure and fix-first list
version: 1.0.0
metadata:
  hermes:
    tags: [security, tenable, vulnerability, posture, ciso]
    category: security
---

# Review Tenable Exposure Posture

## When to Use

The user wants the vulnerability-exposure picture — "what's our Tenable exposure",
"what should we patch first", "give me a CISO vulnerability summary". Uses the
**f0_sectools Tenable** MCP server (read-only). This is the default Tenable focus.

## Tools

Base tool names (runtime may prefix — see the Tenable server README):
`get_vulnerability_summary`, `list_top_vulnerabilities` (set `severity_min`),
`list_scans`. Read-only.

## Procedure

1. Call `get_vulnerability_summary` for the headline — total findings and the
   per-severity breakdown (critical/high/medium/low).
2. Call `list_top_vulnerabilities` (severity_min=high) for the fix-first list,
   ranked by severity then CVSS.
3. Call `list_scans` to check scan freshness — a stale scan means the posture
   picture may be out of date; note it as a caveat.
4. Summarize for the audience: exposure by severity, the top 2-3 vulnerabilities
   to remediate, and any scan-freshness caveat.

## Pitfalls

- Do not claim full coverage if `list_scans` shows stale or missing scans.
- Report only what the tools return; never invent CVE ids or counts.

## Verification

Posture % / counts trace to `get_vulnerability_summary`; each fix-first item traces
to a `list_top_vulnerabilities` finding.

## Discipline (small local models)

- One tool at a time; report only what the tools return.
