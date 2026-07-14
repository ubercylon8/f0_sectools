# Architecture

f0_sectools is a **shared core library + thin per-platform servers**. All
cross-cutting and safety-critical logic lives once in `core/`; each server is a
thin adapter that knows only its platform's API and tool definitions and imports
everything else — findings schema, redaction, auth, pagination, gating, persona
renderers — from `core/`. The safety guarantees are therefore enforceable in one
auditable place and cannot drift across integrations.

```mermaid
flowchart TB
    subgraph model["Local model (private, on your infra)"]
      LM["GPT-OSS · Qwen3 · Gemma 4 · Granite<br/>served via vLLM / llama.cpp / Ollama"]
    end
    subgraph runtime["Agent runtime"]
      RT["Hermes · Claude Code · LM Studio<br/>skills + personas"]
    end
    subgraph servers["Thin MCP servers (read-only + gated writes)"]
      D["defender"]
      E["entra"]
      L["limacharlie"]
      P["projectachilles"]
      I["intune"]
      T["tenable"]
    end
    subgraph core["core/ — shared, safety-critical (imported by every server)"]
      C["findings schema · redaction · auth<br/>pagination · gating + audit · renderers"]
    end
    subgraph platforms["Your security platforms"]
      API["Defender · Entra · LimaCharlie<br/>ProjectAchilles · Intune · Tenable APIs"]
    end

    LM <--> RT
    RT <-->|MCP stdio| servers
    D & E & L & P & I & T --> C
    servers -->|redacted findings| RT
    servers <-->|credentials never leave host| API
```

Every tool returns the normalized [findings schema](../CLAUDE.md#the-findings-schema);
output is redacted at the server boundary before it reaches the runtime. See
[CLAUDE.md](../CLAUDE.md) for the full house rules.
