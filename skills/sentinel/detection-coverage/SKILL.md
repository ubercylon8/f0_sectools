---
name: detection-coverage
description: Review Sentinel analytics rules and MITRE tactic gaps
version: 1.0.0
metadata:
  hermes:
    tags: [security, sentinel, detection-engineering, coverage, mitre]
    category: security
---

# Sentinel Detection Coverage

## When to Use

For the detection-engineer question: "what do we actually detect?", "which
ATT&CK tactics have no rule?", "are our analytics rules enabled?". Also when a
CISO asks whether the SIEM is doing detection or just collection.

## Procedure

Base tool names: `get_detection_coverage`, `list_sentinel_incidents`,
`list_data_sources`.

1. Call `get_detection_coverage`. It reports rule counts and TWO tactic
   figures, never conflated: tactics covered by ALL enabled rules
   (`tactics_covered_all`, including Microsoft-managed rules) and tactics
   covered by CUSTOM, operator-authored rules alone (`tactics_covered_custom`,
   evidence keys `rules_total`, `rules_enabled`, `rules_custom`). Lead with
   the custom figure — it is what the operator actually built.
2. **Only enabled rules count.** A disabled rule contributes to neither
   figure; do not credit coverage for a rule that is off.
3. Call `list_sentinel_incidents` with `status="any"` and compare tactics
   against what `get_detection_coverage` reports. Pass `status="any"`
   deliberately: the tool defaults to open work, but this comparison is about
   the whole population a rule set produced, and closed incidents count toward
   that just as much as open ones. A large incident volume against a small
   custom rule count means most incidents come from a connected product (e.g.
   Defender XDR mirroring into Sentinel) rather than Sentinel analytics —
   that is a real, commonly-missed finding, and it is invisible from the
   queue alone. f0-defender's `list_incidents` shows the same population from
   the EDR side if you need to cross-check which surface is native.
4. Call `list_data_sources`. A tactic can only be covered where the telemetry
   exists: an uncovered tactic with no supporting table is a data gap, not a
   rule gap, and the remediation is different.
5. Report rule gaps and data gaps separately, then name the highest-value
   additions — prioritize tactics missing from `tactics_uncovered_custom`.

## Pitfalls

- **A high "covered overall" number can come almost entirely from built-in
  rules.** On a validated workspace, `tactics_covered_all` showed 12 of 14
  tactics covered, but `tactics_covered_custom` showed only 2 — the other ten
  came from a single Microsoft-managed Fusion rule, not anything the operator
  wrote. Microsoft-managed kinds are `Fusion`,
  `MicrosoftSecurityIncidentCreation`, `MLBehaviorAnalytics`, and
  `ThreatIntelligence`; operator-authored kinds are `Scheduled` and `NRT`.
  Always report the custom figure as the real detection-engineering answer,
  and the overall figure only as context.
- **A disabled rule is not coverage.** `get_detection_coverage` already
  excludes disabled rules from both tactic sets — do not re-add them by
  quoting a rule inventory number as if it were a coverage number.
- **Do not equate incident volume with detection quality.** Mirrored incidents
  inflate the count without any local detection engineering (see Procedure
  step 3).
- **An incident's tactics can legitimately fall outside the 14-tactic matrix
  `get_detection_coverage` measures against.** `list_sentinel_incidents`
  extracts tactics from the incident's own data and can surface values like
  `InhibitResponseFunction`, which belongs to the ICS/OT matrix, not the
  14-tactic enterprise matrix this tool covers. Do not treat such a tactic as
  an enterprise-matrix gap.
- `list_sentinel_incidents` also emits an `owner` evidence field, which is
  either a readable name/UPN or the literal `unassigned`. A queue where every
  incident is `unassigned` is a SOC-hygiene finding worth surfacing on its
  own, separate from detection coverage.
- If the ARM coordinates are unset, `get_detection_coverage` says so — report
  that as missing configuration, not as zero rules.

## Verification

Every coverage or gap claim traces to a `get_detection_coverage` evidence
field. Uncovered tactics are quoted from `tactics_uncovered_custom` (or
`tactics_uncovered_all` when explicitly discussing overall coverage), never
inferred.
