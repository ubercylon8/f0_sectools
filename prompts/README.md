# prompts/

Portable **system prompts** for chat UIs that have **no skill system** — LM
Studio, Open WebUI, or any OpenAI-compatible client where you paste a system
prompt instead of loading skills.

These mirror the Hermes `SOUL.md` + `skills/` so behaviour stays consistent no
matter how f0_sectools is driven. For skills-aware runtimes (Hermes, Claude
Code), use [`../skills/`](../skills/) and (for Hermes) the role profiles in
[`../integrations/hermes/`](../integrations/hermes/) instead.

| File | Use |
|------|-----|
| `f0-sectools-system-prompt.md` | Persona-switchable SOC assistant prompt covering the Defender + Entra tools |
