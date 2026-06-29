---
name: review-validation-fleet
description: Review ProjectAchilles test agents and accepted risk
version: 1.0.0
metadata:
  hermes:
    tags: [security, projectachilles, agents, coverage, risk]
    category: security
---

# Review ProjectAchilles Validation Fleet

## When to Use

The user wants to know whether security **validation is actually running and
covering the estate**, and what risk has been formally accepted — e.g. "are our
test agents healthy", "which endpoints aren't being tested", "what risks have we
accepted". Uses the **f0_sectools ProjectAchilles** MCP server (read-only).

## Tools

Base tool names (runtime may prefix — see the ProjectAchilles server README):
`get_fleet_health`, `list_agents`, `list_risk_acceptances`. Read-only.

## Procedure

1. Call `get_fleet_health` for the fleet rollup — total / online / offline test
   agents (and pending tasks).
2. Call `list_agents` for the roster; note **offline or stale** agents — those
   are coverage gaps (endpoints whose defenses aren't being validated).
3. Call `list_risk_acceptances` for risks deliberately accepted (with
   justification and who accepted them).
4. Summarize: fleet coverage (online vs total), the agents needing attention,
   and the accepted risks worth periodic review.

## Discipline (small local models)

- One tool at a time; report only what the tools return.
- Remember `list_agents` is a bounded roster (a page), while `get_fleet_health`
  gives the true totals — don't confuse the page size with the agent count.
- Relay any `posture` finding (auth / permission / API unavailable) plainly.

## Pitfalls

- Offline agents may be intentional (decommissioned hosts); flag for review,
  don't assume a problem.
- An accepted risk is a decision, not a failure — present it with its
  justification.
- Fleet counts come from `get_fleet_health`; the roster from `list_agents` —
  cite the right source.

## Verification

Fleet numbers trace to `get_fleet_health`; named agents to `list_agents`;
accepted risks to `list_risk_acceptances`.
