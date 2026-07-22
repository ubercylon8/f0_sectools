# FAQ

Answers to the questions evaluators and new operators ask most. Deep dives are
linked throughout; terms are in the [glossary](../reference/glossary.md).

## What is this, in one sentence?

Read-only (plus carefully gated write) MCP tools and portable skills that let
a **small local model** — running entirely on your infrastructure — act as a
security-operations assistant over your own SIEM/XDR, EDR, identity,
vulnerability, and data-security platforms.

## Does any data leave my environment?

No. The model runs locally (vLLM / llama.cpp / Ollama / LM Studio), the MCP
servers run locally, and the only outbound calls are to the security platforms
you configured with your own credentials. No telemetry, no analytics, no
frontier-API dependency. See the [security model](../explanation/security-model.md).

## Can the AI isolate a host / disable a user / change anything on its own?

No. Of the 51 tools, only six change state, and each requires an operator-set
write flag **and** a per-action human confirmation delivered on a channel the
model cannot read, and is audited locally. Both fail-closed paths are shown in
[this transcript](../../examples/transcripts/gated-run-test.md); the mechanism
is in the [security model](../explanation/security-model.md#gated-write-actions).

## What hardware / model do I need?

A machine that can serve a tool-calling model in the **4–20B** class — Qwen3
4B/8B, GPT-OSS 20B, Gemma 4 — at 8-bit quant. On the measured
[scorecard](../../evals/SCORECARD.md), even 4B models drive every server at or
near 100%. Concrete serving guidance and benchmarks:
[runtime performance](../runtime-performance.md).

## Can I use it with Claude or another frontier model instead?

Yes — any MCP-capable runtime works (Claude Code loads the same skills
natively), and a frontier model drives these tools trivially. The engineering
constraint runs the other way: everything is designed so you *don't need* a
cloud model, which is the privacy point. See
[small-model design](../explanation/small-model-design.md).

## Which platforms are supported today?

Eight live-validated servers: Microsoft Defender XDR, Entra ID, LimaCharlie,
ProjectAchilles (read + gated actions), Intune, Tenable VM, and Microsoft
Purview — [tool reference](../reference/tools/README.md). Planned (Wazuh,
Elastic, Splunk, Sentinel, CrowdStrike, SentinelOne, Sophos, MISP,
TheHive, OpenCTI): see the roadmap table in [CLAUDE.md](../../CLAUDE.md#platform-integrations);
contributions follow the recipe in [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Why only ~6 tools per platform when the vendor API has hundreds?

Deliberate. Small-model tool-selection accuracy drops as the registry grows,
so each server exposes a curated, flat, bounded set — and the
[eval harness](../../evals/README.md) measures that models actually drive them
reliably. The official LimaCharlie MCP server (278 tools) is the
frontier-model alternative; it is intentionally not what this project is.

## Do I need all the platforms configured?

No. Configure one `.env.<platform>` and run just that server. Tools for a
permission you haven't granted return an actionable "grant X" posture finding
instead of failing — partial setups degrade gracefully.

## What licenses / permissions do the Microsoft servers need?

Each server's `.env.<platform>.example` documents the exact Graph application
permissions (read-only, admin consent). Notable: Entra Identity Protection
tools need **Entra ID P2**; Purview DLP/insider-risk content needs Purview
licensing and `AuditLogsQuery.Read.All`. Missing license/permission → graceful
posture finding, not a crash.

## Is my security data safe in the model's context window?

Findings are bounded (default 25/page, max 100), summarized, and redacted
(credentials and token-shaped values stripped) before the model sees them. The
operational data that remains — hostnames, alert titles — goes only to *your*
local model. That is the architectural privacy guarantee; details in the
[security model](../explanation/security-model.md#secrets-and-redaction).

## How is this different from f0_library / ProjectAchilles?

Same F0RT1KA ecosystem, opposite directions: `f0_library` is offensive (EDR
detection testing), **f0_sectools is defensive/operational** (posture, triage,
hunting over your platforms), and ProjectAchilles is the validation platform
both connect to. The
[validation-coverage-loop skill](../../skills/cross-platform/validation-coverage-loop/SKILL.md)
closes the circle: weak techniques → detection coverage → retest.

## What's the license? Can I use it commercially?

Apache 2.0 ([LICENSE](../../LICENSE)). Yes, including commercially, per the
license terms.

## Something's broken / a tool never fires — where do I look?

[Troubleshooting](troubleshooting.md) first; per-runtime quirks in each
[runtime guide](README.md#start-here); if you've found a security issue,
[SECURITY.md](../../SECURITY.md).
