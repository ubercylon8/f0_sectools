# Security Policy

## Authorized use

f0_sectools connects AI agents to live security platforms (SIEM/XDR, EDR,
identity, threat intelligence) and can, when explicitly enabled, take response
actions on them. Use it **only** against platforms and tenants you are
authorized to access and operate.

### Safety model

- **Read-only by default.** All tools that query a platform are read-only.
- **Gated write actions.** Any state-changing action (e.g. isolate host,
  disable user, quarantine file, close incident) requires **both**:
  1. an explicit per-platform configuration flag (e.g. `DEFENDER_ALLOW_WRITE=true`), and
  2. a fresh, single-use human confirmation token at execution time.
  Such actions are recorded to a local audit trail.
- **A small local model can never take a write action on its own.** The flag +
  token gate is a hard stop that requires a human in the loop.

### Privacy guarantees

- Credentials are loaded from per-platform `.env` files and are **never logged,
  never included in tool output, never passed into model context, and never
  sent off-host.**
- All tool output is redacted (secrets, tokens, raw PII) before it is returned
  to the agent — including error and exception paths.
- f0_sectools makes no external calls except to the security platforms the
  operator explicitly configures. No telemetry.

## Reporting a vulnerability

If you discover a security vulnerability in f0_sectools, please report it
responsibly. Do **not** open a public issue for a sensitive vulnerability.

Instead, contact the maintainers privately with:

- a description of the issue and its impact,
- steps to reproduce, and
- any suggested remediation.

We will acknowledge your report, investigate, and coordinate a fix and
disclosure timeline with you.

## Scope

This policy covers the f0_sectools codebase (core library, MCP servers, skills,
and eval harness). Vulnerabilities in third-party security platforms themselves
should be reported to their respective vendors.
