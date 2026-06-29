---
name: review-detection-coverage
description: Review LimaCharlie D&R coverage vs recent detections
version: 1.0.0
metadata:
  hermes:
    tags: [security, limacharlie, detection-engineering, coverage, edr]
    category: security
---

# Review LimaCharlie Detection Coverage

## When to Use

The user wants to understand detection posture — e.g. "how's our detection
coverage", "are our D&R rules firing", "review our LimaCharlie detections". This
is the offensive↔defensive loop: rules deployed (often by f0_library) vs what
actually fired. Uses the **f0_sectools LimaCharlie** MCP server (read-only).

## Tools

Base tool names (runtime may prefix — see the LimaCharlie server README):
`get_org_overview`, `list_dr_rules`, `list_detections`. Read-only.

## Procedure

1. Call `get_org_overview` for the baseline: sensor count, D&R rule count, and
   detection volume in the last 24h.
2. Call `list_dr_rules` to enumerate the D&R rules. **Distinguish detection
   rules from output/forwarding rules** (e.g. a rule named `*-to-elasticsearch`
   forwards data; it is not detection coverage).
3. Call `list_detections` (set `hours_back` to the window of interest) and group
   the detections by their category/rule (`cat`).
4. Correlate: which rules are producing detections? Which detection rules exist
   but never fire (a possible gap, a stale rule, or simply no matching activity)?
5. Summarize coverage: number of detection rules, how many fired, detection
   volume, and notable gaps. Recommend tuning noisy rules or adding coverage for
   uncovered techniques.

## Discipline (small local models)

- One tool at a time; report only what the tools return.
- Don't infer that a rule is "broken" just because it has no detections — say it
  "produced no detections in the window".
- Relay any `posture` finding (permission / auth / rate-limited) and stop.

## Pitfalls

- Output/forwarding rules are **not** detection coverage — don't count them.
- `0 detections` can mean a quiet environment OR missing detection rules; check
  the rule list before concluding.
- Detection volume varies hugely by org; compare against the rule set, not an
  absolute number.

## Verification

Rule and detection counts trace to `list_dr_rules` / `list_detections` /
`get_org_overview` findings. Named rules and detection categories are quoted
from the findings, not invented.
