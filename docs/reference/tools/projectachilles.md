<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# `f0-projectachilles` tool reference

Module `f0_projectachilles_mcp.server` · **8 tools** (all read-only) · [server README](../../../servers/projectachilles-mcp/README.md)

## `get_defense_score`

ProjectAchilles defense score — how well controls block/detect simulated attacks.

over_time=false (default) returns the CURRENT score (a snapshot). over_time=true
returns the TREND over the period — use it for any "improving", "declining",
"over time", or "history" question. interval (day|hour) applies only to the trend.

| Parameter | Type | Default |
|---|---|---|
| `days` | `integer` | `30` |
| `over_time` | `boolean` | `False` |
| `interval` | `string` | `"day"` |

Used by skills: [`roll-up-ciso-risk`](../../../skills/cross-platform/ciso-risk-rollup/SKILL.md), [`review-defense-posture`](../../../skills/projectachilles/defense-posture-review/SKILL.md), [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)

## `get_weak_techniques`

Lowest-scoring MITRE techniques — where defenses most often fail.

| Parameter | Type | Default |
|---|---|---|
| `days` | `integer` | `30` |
| `limit` | `integer` | `10` |

Used by skills: [`triage-incident-cross-platform`](../../../skills/cross-platform/triage-incident-cross-platform/SKILL.md), [`validation-coverage-loop`](../../../skills/cross-platform/validation-coverage-loop/SKILL.md), [`analyze-coverage-gaps`](../../../skills/projectachilles/coverage-gap-analysis/SKILL.md), [`review-defense-posture`](../../../skills/projectachilles/defense-posture-review/SKILL.md)

## `list_test_executions`

Test RESULTS / outcomes — how test runs actually did, per host (NOT the test
catalog; for "which tests exist" use find_tests). Use for "results for test X",
"how did the <tag> fleet do", "recent executions that were not blocked". Pass
`test` (a test name), `tag` (a fleet), and/or `hostname` to scope the results to
one run. Two kinds (see the `check_kind` evidence): attack simulations — blocked
vs NOT blocked; cyber-hygiene control checks — passed vs not passed. Bundle runs
roll up into one per-run COMPLIANT/NON-COMPLIANT finding (X/Y controls).

| Parameter | Type | Default |
|---|---|---|
| `days` | `integer` | `7` |
| `limit` | `integer` | `25` |
| `test` | `string` | `""` |
| `tag` | `string` | `""` |
| `hostname` | `string` | `""` |

Used by skills: [`analyze-coverage-gaps`](../../../skills/projectachilles/coverage-gap-analysis/SKILL.md), [`explore-test-catalog`](../../../skills/projectachilles/explore-test-catalog/SKILL.md), [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)

## `list_risk_acceptances`

Risks deliberately accepted (not remediated). status: active|revoked.

| Parameter | Type | Default |
|---|---|---|
| `status` | `"active"` \| `"revoked"` | `"active"` |
| `limit` | `integer` | `50` |

Used by skills: [`review-validation-fleet`](../../../skills/projectachilles/validation-fleet-review/SKILL.md)

## `list_agents`

List ProjectAchilles test agents (endpoints): hostname, OS, status.

| Parameter | Type | Default |
|---|---|---|
| `status` | `string` \| `null` | `None` |
| `online_only` | `boolean` | `False` |
| `limit` | `integer` | `50` |

Used by skills: [`review-validation-fleet`](../../../skills/projectachilles/validation-fleet-review/SKILL.md)

## `get_fleet_health`

ProjectAchilles validation-agent fleet health: attack-simulation agents online/offline.

The ProjectAchilles breach-&-attack-simulation validation fleet — not LimaCharlie
endpoint sensors (use get_org_overview) or Microsoft tenant posture (use get_secure_score).

*No parameters.*

Used by skills: [`review-validation-fleet`](../../../skills/projectachilles/validation-fleet-review/SKILL.md)

## `find_tests`

Search the ProjectAchilles TEST CATALOG — the library of tests that CAN be run,
not run history (use list_test_executions for history). by selects the dimension:
technique|actor|tactic|category|tag|keyword. Returns a match count plus the matching
tests (name, MITRE techniques, threat actor, OS, severity).

| Parameter | Type | Default |
|---|---|---|
| `by` | `"technique"` \| `"actor"` \| `"tactic"` \| `"category"` \| `"tag"` \| `"keyword"` | *(required)* |
| `value` | `string` | *(required)* |
| `limit` | `integer` | `25` |

Used by skills: [`explore-test-catalog`](../../../skills/projectachilles/explore-test-catalog/SKILL.md), [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)

## `get_test`

Full detail for ONE specific test — use for "what does test X cover / do",
"details on the <name> test". Returns description, OS/target, complexity, tactics,
tags, MITRE techniques. test_id is a test uuid or an exact test name (to SEARCH or
LIST across many tests use find_tests instead).

| Parameter | Type | Default |
|---|---|---|
| `test_id` | `string` | *(required)* |

Used by skills: [`explore-test-catalog`](../../../skills/projectachilles/explore-test-catalog/SKILL.md), [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)
