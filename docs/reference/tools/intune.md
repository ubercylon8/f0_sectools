<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# `f0-intune` tool reference

Module `f0_intune_mcp.server` · **6 tools** (all read-only) · [server README](../../../servers/intune-mcp/README.md)

## `list_managed_devices`

List Intune-managed devices with compliance/encryption/owner/sync state.

compliance: one of all|compliant|noncompliant|ingraceperiod|unknown. limit: max devices.

| Parameter | Type | Default |
|---|---|---|
| `compliance` | `"all"` \| `"compliant"` \| `"noncompliant"` \| `"ingraceperiod"` \| `"unknown"` | `"all"` |
| `limit` | `integer` | `25` |

Used by skills: [`intune-coverage-gap-review`](../../../skills/intune/coverage-gap-review/SKILL.md), [`intune-device-compliance-review`](../../../skills/intune/device-compliance-review/SKILL.md)

## `get_compliance_summary`

Intune device-compliance rollup: how many managed devices are compliant vs not.

*No parameters.*

Used by skills: [`roll-up-ciso-risk`](../../../skills/cross-platform/ciso-risk-rollup/SKILL.md), [`intune-coverage-gap-review`](../../../skills/intune/coverage-gap-review/SKILL.md), [`intune-device-compliance-review`](../../../skills/intune/device-compliance-review/SKILL.md)

## `get_managed_device`

Get one Intune-managed device by its device name (compliance, encryption, owner, sync).

| Parameter | Type | Default |
|---|---|---|
| `device_name` | `string` | *(required)* |

Used by skills: [`intune-device-triage`](../../../skills/intune/device-triage/SKILL.md)

## `list_stale_devices`

List Intune devices not synced in the last `days` (coverage drift / abandoned).

| Parameter | Type | Default |
|---|---|---|
| `days` | `integer` | `30` |
| `limit` | `integer` | `25` |

Used by skills: [`intune-coverage-gap-review`](../../../skills/intune/coverage-gap-review/SKILL.md)

## `list_compliance_policies`

List Intune device COMPLIANCE POLICIES.

Rules that define whether a device is compliant.

| Parameter | Type | Default |
|---|---|---|
| `limit` | `integer` | `25` |

Used by skills: [`intune-device-compliance-review`](../../../skills/intune/device-compliance-review/SKILL.md)

## `list_configuration_profiles`

List Intune device CONFIGURATION PROFILES.

Settings pushed to devices (not the compliance rules).

| Parameter | Type | Default |
|---|---|---|
| `limit` | `integer` | `25` |
