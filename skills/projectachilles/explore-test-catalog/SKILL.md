---
name: explore-test-catalog
description: Explore the ProjectAchilles test catalog by technique/actor
version: 1.0.0
metadata:
  hermes:
    tags: [security, projectachilles, catalog, mitre, threat-intel]
    category: security
---

# Explore the ProjectAchilles Test Catalog

## When to Use

The user wants to know **what tests exist** — e.g. "how many tests do we have for
T1110", "do we have anything for APT29", "list our cyber-hygiene checks", "what
does the Kerberoast test do". Uses the **f0_sectools ProjectAchilles** MCP server
(read-only). This is the **library of what can be run** — not run history (that's
`list_test_executions`).

## Tools

Base tool names (runtime may prefix — see the ProjectAchilles server README):
`find_tests`, `get_test`. Read-only.

## Procedure

1. Pick the dimension the user is asking about and call `find_tests` with the
   matching `by`: `technique` (e.g. T1110), `actor` (e.g. APT29), `tactic`
   (e.g. TA0006), `category` (intel-driven / mitre-top10 / cyber-hygiene /
   phase-aligned), `tag`, or `keyword` for free text.
2. Read the **leading summary finding** for the exact match count — it is correct
   even when the per-test list is capped at `limit`. Report that count directly.
3. To explain a specific test, call `get_test` with its uuid (from a `find_tests`
   result) or its exact name — it returns the description, OS/target, complexity,
   tactics, tags, and MITRE techniques.

## Discipline (small local models)

- One tool at a time; report only the tests returned.
- Lead with the count from the summary finding; don't re-count the truncated list.
- Relay any `posture` finding (auth / permission / API unavailable) plainly.

## Pitfalls

- **Catalog ≠ history.** A `find_tests` result means the test *exists in the
  library*, not that it was ever run. For "what did we run / block", use
  `list_test_executions`.
- If `get_test` says "specify by uuid", the name was ambiguous — pick the uuid
  from the listed candidates and call again.
- Don't invent techniques, actors, or tests not present in a finding.

## Verification

Each reported test maps to a `find_tests` per-test finding (or a `get_test`
detail finding); the count comes from the summary finding's `total_matches`.
