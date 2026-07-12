---
name: intune-device-triage
description: Check a device's Intune state during triage
version: 1.0.0
metadata:
  hermes:
    tags: [security, intune, soc, incident-response, endpoint, triage]
    category: security
---

# Intune Device Triage

## When to Use

During incident triage the user has a **specific device** — often from a Defender
incident or alert — and wants its Intune management state: "is this host compliant
and encrypted", "what's the Intune state of device X", "is the device in this
incident managed". A device-first, two-server pivot (Intune, plus Defender for the
device name). Uses the **f0_sectools Intune** MCP server (read-only); may read
Defender for context. For the full four-server incident picture, use
`cross-platform/triage-incident-cross-platform` instead.

## Tools

Base tool names (runtime may prefix — see each server README):
- Intune: `get_managed_device`
- Defender (optional, for the device name): `list_incidents`, `list_alerts`

All read-only.

## Procedure

Work **one tool at a time**: call, read the result, then decide the next step.

1. **Get the device name.** From the user directly, or from a Defender
   `list_incidents` / `list_alerts` finding's device entity.
2. **Look it up.** Call `get_managed_device` with that `device_name`.
3. **Report the management state:** compliance state, encryption, OS, owner
   (company vs personal), last sync time, and the assigned user.
4. **Turn it into a triage judgment:** e.g. "personal-owned, unencrypted, and
   noncompliant → elevated risk; verify/contain"; or "company, compliant,
   encrypted, synced today → lower device risk".

## Discipline (small local models)

- One tool at a time; report only what the finding contains.
- Do not assert isolation/remediation happened — these tools are read-only.
- Relay any `posture` finding (permission / license / throttle) plainly.

## Pitfalls

- A Defender device name may differ from the Intune `deviceName`.
  `get_managed_device` returns a graceful "no managed device named X" finding when
  there is no match — try the hostname variant (short name vs FQDN) rather than
  concluding the device is unmanaged.
- Personal ("BYOD") devices legitimately expose less; note it, don't treat every
  gap as a misconfiguration.

## Verification

The reported state comes entirely from the `get_managed_device` finding
(`compliance`, `encrypted`, `os`, `owner`, `last_sync`, `user`); the device name
traces back to the Defender finding or the user's request.
