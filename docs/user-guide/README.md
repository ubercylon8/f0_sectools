# f0_sectools User Guide

How to **use** f0_sectools — connect its read-only security tools to a local
model through the agent platform of your choice, and drive them with skills and
role personas.

> **This is a living guide.** It grows with the software. When a platform
> integration, server, skill, or persona is added, update the matrix below and
> add the relevant runtime/workflow page. Keep it accurate over comprehensive.

## What you get

Read-only AI tooling over your own security platforms, running on **your**
infrastructure with a **local open-weights model** (GPT-OSS, Gemma 4, Qwen3).
Nothing leaves the host. Today: Microsoft **Defender** and **Entra ID**.

## Start here

1. **[Getting started](getting-started.md)** — prerequisites, checkout, install,
   credentials, and a first verification. Do this once; every runtime needs it.
2. Pick your runtime:
   - **[Hermes Agent](runtimes/hermes.md)** — recommended; skills-aware, native
     MCP, personas.
   - **[LM Studio](runtimes/lm-studio.md)** — turnkey desktop app (model + MCP +
     chat).
   - **[Open WebUI](runtimes/open-webui.md)** — web UI (needs the `mcpo` bridge).
   - **[Claude Code](runtimes/claude-code.md)** — terminal agent (skills + MCP).
   - Generic vLLM/llama.cpp + any MCP client → see
     [running with local models](../running-with-local-models.md).
3. **[Using skills & personas](using-skills-and-personas.md)** — what the
   playbooks and the four role lenses do.
4. **[Prompting](prompting.md)** — how to phrase requests so a small local model
   reliably drives the tools (matters a lot — read this).
5. **[Workflows](workflows.md)** — example end-to-end tasks (posture, triage,
   hunt) with the prompts to use.
6. **[Troubleshooting](troubleshooting.md)** — throttling, missing permissions,
   tools not firing.

## Support matrix (living — update as the project grows)

### Security platforms (servers)

| Platform | Server | Status | Tools |
|----------|--------|--------|-------|
| Microsoft Defender XDR | `f0-defender-mcp` | ✅ live-validated | secure score, incidents, alerts, hunting (KQL) |
| Microsoft Entra ID | `f0-entra-mcp` | ✅ live-validated | risky users*, risk detections*, conditional access, privileged roles |
| LimaCharlie | `f0-limacharlie-mcp` | ✅ live-validated | org overview, sensors, D&R rules, detections, LCQL telemetry |
| ProjectAchilles | `f0-projectachilles-mcp` | ✅ live-validated | defense score, score trend, weak techniques, test results, risk acceptances, agents, fleet health |
| Microsoft Intune | `f0-intune-mcp` | ✅ live-validated | managed devices, compliance summary, stale devices, compliance policies, config profiles |

\* Identity Protection tools require Entra ID **P2** + the relevant Graph
permissions; otherwise they return a graceful "permission/throttled" finding.

### Agent runtimes

| Runtime | Skills | Personas | MCP transport | Guide |
|---------|--------|----------|---------------|-------|
| Hermes Agent | ✅ native | ✅ profiles | stdio | [hermes.md](runtimes/hermes.md) |
| Claude Code | ✅ native | via prompt | stdio | [claude-code.md](runtimes/claude-code.md) |
| LM Studio | ➖ system prompt | ➖ prompt modes | stdio | [lm-studio.md](runtimes/lm-studio.md) |
| Open WebUI | ➖ system prompt | ➖ prompt modes | HTTP via `mcpo` | [open-webui.md](runtimes/open-webui.md) |

✅ native skill system · ➖ no skill system → use the portable prompt in
[`prompts/`](../../prompts/).

### Personas

CISO · threat hunter · detection engineer · security engineer — see
[using skills & personas](using-skills-and-personas.md).
