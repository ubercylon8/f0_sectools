# Prompting f0_sectools — writing effective requests

How you phrase a request matters a lot when a **small local model** is driving the
tools. A frontier model forgives vague asks; a small model (GPT-OSS, Gemma, Qwen3)
is far more sensitive to specificity. This page is how to ask so the model
reliably picks the right tool and fills the right arguments.

> **Why this matters (measured):** in our own [eval](../../evals/), the request
> *"hunt for PowerShell downloads today"* succeeded **100%** of the time while
> *"run an advanced hunting query for suspicious sign-ins"* succeeded **0%** —
> same model, same tool, the only difference was **how it was phrased.**

## The three prompt layers (what's set for you vs what you control)

| Layer | What it is | Who sets it |
|-------|------------|-------------|
| System prompt | the model's standing instructions / persona | already shipped — [`prompts/`](../../prompts/) + Hermes `SOUL.md` |
| Tool descriptions | the per-tool guidance the model reads | already maintained (tuned against the eval) |
| **Your request** | the sentence you type | **you** — this page |

You only control the third layer. The other two are done; your phrasing is what's
left to get right.

## Five rules for prompting a small local model

### 1. Name the platform, the thing, and the time window
Give the model the nouns it needs. *"Investigate the endpoint **web-01** in
LimaCharlie"* beats *"look into that host"*. *"high-severity Defender incidents in
the **last 24h**"* beats *"recent issues"*.

### 2. Concrete beats vague
A vague ask makes the model guess which tool and what arguments. Be concrete about
the outcome you want.

| ✅ Concrete | ❌ Vague |
|------------|---------|
| "What's our Microsoft Secure Score?" | "How are we doing?" |
| "List conditional access policies that are disabled" | "Check our Entra config" |
| "Which MITRE techniques are we weakest against?" | "Tell me about ProjectAchilles" |

### 3. One step at a time
Small models are most reliable doing a single tool call, reading the result, then
deciding the next. Ask for one thing; let the model come back before you pivot.
Multi-part requests ("triage incidents and then hunt and then summarize for the
board") are where small models drop steps.

### 4. Set the lens (persona / mode)
Prefix with the role you want so the output is framed correctly:
*"**As a CISO**, give me a posture summary"* · *"**As a threat hunter**, look into
the exfiltration incident"*. In Hermes use `/personality <name>`; elsewhere just
say "as a …". See [using skills & personas](using-skills-and-personas.md).

### 5. For hunts / free-text queries, give or template the query
Some tools take a **free-text query** the model must write — Defender
`run_hunting_query` (KQL) and LimaCharlie `query_telemetry` (LCQL). A small model
can usually manage **common KQL**, but **struggles to invent rarer syntax like
LCQL** from a vague prompt. So:
- **Be specific** ("hunt for **new processes** today") rather than "hunt for stuff", **or**
- **Supply the query** — *"Run this LCQL: `-24h | plat == windows | NEW_PROCESS | * | event/FILE_PATH`"* — and the model just passes it through, **or**
- **Use a starter** from [`skills/limacharlie/threat-hunt/references/lcql-starters.md`](../../skills/limacharlie/threat-hunt/references/lcql-starters.md) (LCQL) and tweak the filter.

If the model keeps failing to *write* a query, that's a model-size limit, not a
you-problem — supply the query, or use a stronger model.

## Good prompts per platform

| Platform | ✅ Try | Notes |
|----------|--------|-------|
| Defender | "List active high-severity incidents" · "Hunt for PowerShell that downloaded files today" | name severity + time window |
| Entra | "Which users are risky right now?" · "List disabled conditional access policies" | — |
| LimaCharlie | "Investigate sensor web-01" · "What detections fired in the last 24h?" | for hunts, supply/template the LCQL (rule 5) |
| ProjectAchilles | "What's our defense score?" · "Is our defense score **improving over time**?" | say "over time / trend" so it picks the trend tool, not the snapshot |

## What to expect back

Tools return **findings** (severity, entity, evidence, recommended action), not
prose tables — the model summarizes them for you. If something isn't reachable you
get a **posture finding** instead of an error, e.g. *"Permission 'X' not granted"*,
*"Rate limited — retry shortly"*, or *"API temporarily unavailable"*. Relay those
as-is; see [troubleshooting](troubleshooting.md).

## Picking a model that's good enough

If a *specific, well-phrased* request still picks the wrong tool, the model may be
too small for that tool. Measure it: run the
[eval harness](getting-started.md#optional-measure-your-models-tool-calling-reliability)
against your model — a low score on a tool is a signal to use a stronger model (or
for us to simplify the tool), not to keep fighting the prompt.
