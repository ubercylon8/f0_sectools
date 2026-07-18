---
name: validation-coverage-loop
description: Weak techniques -> LC coverage -> retest recommendation
version: 1.0.0
metadata:
  hermes:
    tags: [security, detection-engineering, projectachilles, limacharlie, cross-platform]
    category: security
---

# Close the Offensive/Defensive Loop

## When to Use

The user wants to close the loop between **offensive validation** and
**defensive coverage**: which MITRE techniques our ProjectAchilles attack
simulations keep getting through, whether LimaCharlie has a detection rule for
them, and what to re-test. Triggers: "where are we weak and do we have coverage",
"what should we re-test", "close the offensive/defensive loop", "turn our weak
techniques into a retest plan".

Uses two **f0_sectools** MCP servers, read-only: ProjectAchilles and LimaCharlie.
The retest step targets **f0_library** — a separate offensive repo, **not** an MCP
server here — so this skill **recommends** a test to run there; it does not run it.

## Tools

Base tool names (runtime prefixes them):
- ProjectAchilles: `get_weak_techniques`
- LimaCharlie: `list_dr_rules`, `list_detections`

All read-only.

## Procedure

One tool at a time.

1. **Weak techniques (ProjectAchilles).** Call `get_weak_techniques`. These are
   the MITRE techniques our attack simulations most often get through. Note each
   technique's **MITRE id** and score.
2. **Coverage (LimaCharlie).** Call `list_dr_rules`. For each weak technique, look
   for a detection rule that would catch it — matched by the rule's name or
   content referencing the technique (D&R rules don't always tag a MITRE id, so
   this is **best-effort**). Then call `list_detections` to see whether that rule
   has actually fired recently. A rule that exists but never fires is weak
   coverage too.
3. **Recommend a retest (f0_library — do not execute).** For each technique that
   is **weak AND lacks effective coverage** (no rule, or a rule that isn't
   firing), recommend re-running the matching **f0_library** test to re-validate
   *after* a detection rule is added or fixed. Name the technique and the test.
   State plainly: f0_library is the separate offensive repo the operator runs —
   this skill only produces the recommendation.

   To actually run or schedule the covering test from here, switch to the
   run-validation-test skill (ProjectAchilles actions server, gated).

## Pitfalls

- **Technique ↔ rule matching is best-effort.** If you can't tie a weak technique
  to a specific rule by name/content, say "no clear LimaCharlie rule found for
  <technique>" rather than assuming coverage exists or doesn't.
- **Recommend, don't execute.** This skill never runs an f0_library test or
  changes a D&R rule — it hands the operator a prioritized retest list.
- **Never invent** technique scores, rule names, or detection counts.

## Small models

This chains two servers with per-technique matching. It favours a **capable local
model** (e.g. GPT-OSS 20B). On smaller models, run it for a **single** weak
technique at a time (get one technique from `get_weak_techniques`, then check just
that one against `list_dr_rules`) to keep each step simple.

## Verification

- Every recommendation ties a specific **weak technique** (from
  `get_weak_techniques`) to its **coverage status** (from `list_dr_rules` /
  `list_detections`), or explicitly says the coverage couldn't be determined.
- The f0_library retest is framed as a **recommendation**, never as an action taken.
- No values invented; no state changed.
