# f0_sectools — Security-Operations Tools & Skills for Local AI Agents

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

> **Project naming:** **`f0_sectools`** is this software. **F0RT1KA** is the parent organization / brand. It is part of the [ProjectAchilles](https://projectachilles.io/) ecosystem, and the defensive / operational counterpart to [`f0_library`](https://github.com/) (offensive EDR detection testing).

## What it is

**f0_sectools** is an open-source library of **tools, skills, and MCP servers** that let AI agents connect to security platforms — SIEM/XDR, EDR, identity, and threat intelligence — to **understand security posture, assess risk, and help decide on the right course of action**.

It serves **SOC analysts, security engineers, threat hunters, and CISOs**, giving each the same underlying evidence rendered for their altitude — tactical triage, configuration fixes, hunting timelines, or executive risk rollups.

## Why it's different: privacy-first, small local models

f0_sectools is built to run with **small, open-weight models** — GPT-OSS (20b/120b), Gemma 4, Qwen3 — served **on your own infrastructure** via **vLLM** or **llama.cpp**. No telemetry. No sensitive security data leaving the host. No dependency on a frontier cloud API.

That constraint shapes everything: tools are deliberately designed so a *small, private* model can drive them **reliably**, and an evaluation harness **measures** that callability so it does not silently erode.

## Core principles

- **Read-only by default.** Querying and analysis are always safe. Any action that changes state on a live platform (isolate host, disable user, quarantine) is **gated** behind an explicit config flag **and** a per-action human confirmation token — a local model can never trigger it alone.
- **Privacy by construction.** Per-platform `.env` credentials are never logged, never sent to the model, and never leave the host. All output is redacted before it reaches the agent.
- **Structured findings.** Every tool returns a normalized findings schema, then renders it per persona — predictable for agents to parse and chain.
- **Small-model-safe by design.** Flat argument schemas, short enums, few tools per server, bounded output.

## Supported platforms (target roadmap)

SIEM/XDR: **Wazuh** (reference implementation), **Elastic/OpenSearch**, **Splunk**, **Microsoft Sentinel**
EDR: **Microsoft Defender**, **CrowdStrike**, **SentinelOne**, **Sophos**
Identity: **Microsoft Entra ID / Azure**
Threat intel & IR: **MISP**, **TheHive / Cortex**, **OpenCTI**

## Repository layout

```
core/          Shared package: findings schema, redaction, auth, paging,
               small-model helpers, gated-action machinery, persona renderers.
servers/       One thin MCP server per platform (imports core).
skills/        Portable agentskills.io playbooks (work in Hermes, Claude Code, …).
integrations/  Runtime-specific wiring (e.g. Hermes config + personas).
prompts/       Portable system prompts for non-skill UIs (LM Studio, Open WebUI).
evals/         Small-model tool-calling evaluation harness + task sets.
docs/          Documentation, including the user guide.
CLAUDE.md      Build guide / house rules for agents working in this repo.
```

## Using f0_sectools

See the **[User Guide](docs/user-guide/README.md)** — getting started, per-runtime
setup (Hermes, LM Studio, Open WebUI, Claude Code), skills & personas, example
workflows, and troubleshooting.

## Status

**Working today:** the `core/` foundation; the **Microsoft Defender**, **Microsoft
Entra ID**, **LimaCharlie**, **ProjectAchilles**, and **Microsoft Intune** MCP
servers (all live-validated); the eval harness; seventeen skills; the four role
personas; and the Hermes integration. Next: more platforms.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Security and authorized-use guidance is in [SECURITY.md](SECURITY.md).
