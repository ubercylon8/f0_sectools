<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# Skills catalog

**26 portable [agentskills.io](https://agentskills.io) skills** — one set, loaded unmodified by every skills-aware runtime (Hermes, Claude Code, pi, opencode). Each links to its `SKILL.md` playbook. See [using skills & personas](../user-guide/using-skills-and-personas.md) for how to invoke them.

## cross-platform

| Skill | Description | Version | Tags |
|---|---|---|---|
| [`roll-up-ciso-risk`](../../skills/cross-platform/ciso-risk-rollup/SKILL.md) | Executive risk rollup across all security platforms | 1.0.0 | security, ciso, risk, posture, cross-platform, executive |
| [`triage-incident-cross-platform`](../../skills/cross-platform/triage-incident-cross-platform/SKILL.md) | Triage a Defender incident across Entra, LimaCharlie & PA | 1.0.0 | security, soc, incident-response, cross-platform, correlation |
| [`validation-coverage-loop`](../../skills/cross-platform/validation-coverage-loop/SKILL.md) | Weak techniques -> LC coverage -> retest recommendation | 1.0.0 | security, detection-engineering, projectachilles, limacharlie, cross-platform |

## defender

| Skill | Description | Version | Tags |
|---|---|---|---|
| [`defender-posture-summary`](../../skills/defender/posture-summary/SKILL.md) | Summarize Defender security posture for leadership | 1.0.0 | security, posture, defender, ciso, reporting |
| [`defender-threat-hunt`](../../skills/defender/threat-hunt/SKILL.md) | Run guided Microsoft Defender advanced hunting (KQL) | 1.0.0 | security, threat-hunting, defender, kql |
| [`triage-defender-incident`](../../skills/defender/triage-incident/SKILL.md) | Triage a Microsoft Defender incident end-to-end | 1.0.0 | security, soc, defender, incident-response |

## entra

| Skill | Description | Version | Tags |
|---|---|---|---|
| [`audit-conditional-access`](../../skills/entra/conditional-access-audit/SKILL.md) | Audit Entra conditional access policies for gaps | 1.0.0 | security, identity, entra, conditional-access, hardening |
| [`review-entra-identity-risk`](../../skills/entra/identity-risk-review/SKILL.md) | Review Entra ID Protection risky users and detections | 1.0.0 | security, identity, entra, risk, identity-protection |
| [`review-privileged-access`](../../skills/entra/privileged-access-review/SKILL.md) | Review Entra privileged directory role assignments | 1.0.0 | security, identity, entra, privileged-access, hardening |

## intune

| Skill | Description | Version | Tags |
|---|---|---|---|
| [`intune-coverage-gap-review`](../../skills/intune/coverage-gap-review/SKILL.md) | Find Intune device coverage and compliance gaps | 1.0.0 | security, intune, compliance, gaps, endpoint, security-engineering |
| [`intune-device-compliance-review`](../../skills/intune/device-compliance-review/SKILL.md) | Review Intune device compliance posture | 1.0.0 | security, posture, intune, compliance, ciso, reporting |
| [`intune-device-triage`](../../skills/intune/device-triage/SKILL.md) | Check a device's Intune state during triage | 1.0.0 | security, intune, soc, incident-response, endpoint, triage |

## limacharlie

| Skill | Description | Version | Tags |
|---|---|---|---|
| [`review-detection-coverage`](../../skills/limacharlie/detection-coverage-review/SKILL.md) | Review LimaCharlie D&R coverage vs recent detections | 1.0.0 | security, limacharlie, detection-engineering, coverage, edr |
| [`investigate-lc-endpoint`](../../skills/limacharlie/endpoint-investigation/SKILL.md) | Investigate a LimaCharlie endpoint and its activity | 1.0.0 | security, limacharlie, edr, endpoint, investigation |
| [`limacharlie-threat-hunt`](../../skills/limacharlie/threat-hunt/SKILL.md) | Run guided LimaCharlie LCQL telemetry hunts | 1.0.0 | security, limacharlie, threat-hunting, lcql, edr |

## projectachilles

| Skill | Description | Version | Tags |
|---|---|---|---|
| [`analyze-coverage-gaps`](../../skills/projectachilles/coverage-gap-analysis/SKILL.md) | Find ProjectAchilles control gaps (unblocked attacks) | 1.0.0 | security, projectachilles, detection-engineering, gaps, mitre |
| [`review-defense-posture`](../../skills/projectachilles/defense-posture-review/SKILL.md) | Review ProjectAchilles defense posture and trend | 1.0.0 | security, projectachilles, posture, ciso, validation |
| [`explore-test-catalog`](../../skills/projectachilles/explore-test-catalog/SKILL.md) | Explore the ProjectAchilles test catalog by technique/actor | 1.0.0 | security, projectachilles, catalog, mitre, threat-intel |
| [`run-validation-test`](../../skills/projectachilles/run-validation-test/SKILL.md) | Run or schedule a ProjectAchilles validation test (gated) | 1.0.0 | security, projectachilles, validation, gated-write, detection-engineer |
| [`review-validation-fleet`](../../skills/projectachilles/validation-fleet-review/SKILL.md) | Review ProjectAchilles test agents and accepted risk | 1.0.0 | security, projectachilles, agents, coverage, risk |

## purview

| Skill | Description | Version | Tags |
|---|---|---|---|
| [`investigate-audit-activity`](../../skills/purview/audit-investigation/SKILL.md) | Search the M365 unified audit log for user activity | 1.0.0 | security, purview, audit, investigation, hunter |
| [`review-data-risk`](../../skills/purview/data-risk-review/SKILL.md) | Review Purview data-risk posture (DLP, labels, IRM) | 1.0.0 | security, purview, dlp, data-risk, ciso |
| [`triage-dlp-alerts`](../../skills/purview/dlp-alert-triage/SKILL.md) | Triage Microsoft Purview DLP alerts by severity | 1.0.0 | security, purview, dlp, soc, triage |

## tenable

| Skill | Description | Version | Tags |
|---|---|---|---|
| [`review-exposure-posture`](../../skills/tenable/exposure-posture-review/SKILL.md) | Review Tenable vulnerability exposure and fix-first list | 1.0.0 | security, tenable, vulnerability, posture, ciso |
| [`triage-host-vulnerabilities`](../../skills/tenable/host-vulnerability-triage/SKILL.md) | Enumerate and triage one host's Tenable vulnerabilities | 1.0.0 | security, tenable, vulnerability, host, soc |
| [`review-scan-coverage`](../../skills/tenable/scan-coverage-review/SKILL.md) | Review Tenable scan coverage and freshness gaps | 1.0.0 | security, tenable, scans, coverage, engineer |
