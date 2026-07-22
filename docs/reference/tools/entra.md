<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# `f0-entra` tool reference

Module `f0_entra_mcp.server` · **4 tools** (all read-only) · [server README](../../../servers/entra-mcp/README.md)

## `list_risky_users`

List Entra ID Protection risky users (requires Entra ID P2).

| Parameter | Type | Default |
|---|---|---|
| `limit` | `integer` | `25` |

Used by skills: [`triage-incident-cross-platform`](../../../skills/cross-platform/triage-incident-cross-platform/SKILL.md), [`review-entra-identity-risk`](../../../skills/entra/identity-risk-review/SKILL.md)

## `list_risk_detections`

List Entra ID Protection risk detections (requires Entra ID P2).

| Parameter | Type | Default |
|---|---|---|
| `limit` | `integer` | `25` |

Used by skills: [`triage-incident-cross-platform`](../../../skills/cross-platform/triage-incident-cross-platform/SKILL.md), [`review-entra-identity-risk`](../../../skills/entra/identity-risk-review/SKILL.md)

## `list_conditional_access_policies`

List Conditional Access policies, flagging disabled and report-only ones.

*No parameters.*

Used by skills: [`audit-conditional-access`](../../../skills/entra/conditional-access-audit/SKILL.md)

## `list_privileged_role_assignments`

List directory role assignments, highlighting critical privileged roles.

Critical roles first; returns one bounded page with a "more available" note.

| Parameter | Type | Default |
|---|---|---|
| `limit` | `integer` | `25` |

Used by skills: [`review-privileged-access`](../../../skills/entra/privileged-access-review/SKILL.md)
