---
name: analyze-coverage-gaps
description: Find ProjectAchilles control gaps (unblocked attacks)
version: 1.0.0
metadata:
  hermes:
    tags: [security, projectachilles, detection-engineering, gaps, mitre]
    category: security
---

# Analyze ProjectAchilles Coverage Gaps

## When to Use

The user wants to know **where defenses are failing and what to fix** — e.g.
"which attacks aren't we blocking", "where are our control gaps", "what should we
remediate first". Uses the **f0_sectools ProjectAchilles** MCP server
(read-only).

## Tools

Base tool names (runtime may prefix — see the ProjectAchilles server README):
`get_weak_techniques`, `list_test_executions`. Read-only.

## Procedure

1. Call `get_weak_techniques` for the lowest-scoring MITRE techniques (the
   systemic gaps), each with a coverage % and severity.
2. Call `list_test_executions` and focus on the results marked **NOT blocked**
   (and "detected, not blocked") — these are concrete failures, per host.
3. Correlate: which weak techniques show up as actual unblocked executions, and
   on which endpoints?
4. Prioritize by severity and technique impact, then recommend specific control
   or detection changes (e.g. a blocking rule, an EDR policy, hardening) for the
   top gaps.

## Discipline (small local models)

- One tool at a time; report only the techniques and executions returned.
- Lead with the highest-severity unblocked results; don't bury them.
- Relay any `posture` finding (auth / permission / API unavailable) plainly.

## Pitfalls

- A "blocked" result is good news — don't report it as a gap; focus on NOT
  blocked / detected-not-blocked.
- Low-scoring techniques with very few executions may be noise; weigh by count.
- Recommend fixes grounded in the findings; don't invent techniques or hosts.

## Verification

Each named gap maps to a `get_weak_techniques` finding and/or a NOT-blocked
`list_test_executions` finding, with the host taken from the finding.
