---
name: New platform server request
about: Propose a new security platform integration
title: "[platform] "
labels: enhancement, new-platform
---

**Platform** (name + product tier, e.g. "Splunk Enterprise Security")

**Category** (SIEM/XDR · EDR · Identity · Threat intel/IR · Vuln mgmt)

**Auth model** (API key / OAuth2 / vendor SDK / other) — link the auth docs.

**Read capabilities wanted** (the ≤ ~8 flat read tools you'd expect — e.g.
"list detections", "get host", "search telemetry")

**Gated write actions?** (any state-changing action, e.g. "isolate host" —
these are read-only-by-default and gated behind flag + confirmation token)

**API docs / references**

**Why it's valuable** (what SOC/engineer/hunter/CISO question it answers)
