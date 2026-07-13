---
name: review-scan-coverage
description: Review Tenable scan coverage and freshness gaps
version: 1.0.0
metadata:
  hermes:
    tags: [security, tenable, scans, coverage, engineer]
    category: security
---

# Review Tenable Scan Coverage

## When to Use

The user wants to know whether scanning is actually covering the environment —
"are our Tenable scans running", "what's our scan coverage", "any blind spots".
Uses the **f0_sectools Tenable** MCP server (read-only).

## Tools

Base tool names: `list_scans` (scan inventory + status + last-run),
`list_assets` (what's in the inventory). Read-only.

## Procedure

1. Call `list_scans` — review each scan's status and last-run time; flag any that
   are failed, disabled, or stale (not run recently).
2. Call `list_assets` to gauge the asset inventory the scans should be covering.
3. Summarize: which scans are healthy vs stale/failed, and where coverage looks
   thin (assets present but scans not recent).

## Pitfalls

- "Completed" status with an old last-run is still stale — judge on freshness, not
  status alone.
- Report only what the tools return.

## Verification

Each coverage claim traces to a `list_scans` status/last-run value.

## Discipline (small local models)

- One tool at a time; report only what the tools return.
