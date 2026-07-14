# Changelog

All notable changes to f0_sectools are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-14

Initial public release.

### Added

- **Shared `core/`** — findings schema, redaction (applied to all output incl.
  error paths), per-platform `.env` auth, pagination, gated-write machinery +
  audit trail, and persona renderers.
- **Six live-validated MCP servers** — 34 registered tools (32 read + Defender's
  2 gated writes): `defender`, `entra`, `limacharlie`, `projectachilles`,
  `intune`, `tenable`.
- **20 portable [agentskills.io](https://agentskills.io) skills** across the six
  platforms plus cross-platform correlation playbooks.
- **Four role personas** (CISO, threat hunter, detection engineer, security
  engineer) and a **Hermes** integration.
- **Small-model tool-calling eval harness + scorecard** — measures tool-selection
  and argument-filling accuracy per server and across the combined 34-tool
  registry.
- **CI** — tests, ruff, mypy (strict, scoped to shipped source), secret scan
  (gitleaks), and Semgrep as hard gates.
- User guide, runtime-performance guide, and architecture doc.

### Security

- Read-only by default; state-changing actions gated behind a config flag **and**
  a single-use human confirmation token, and audited.
- Credentials never logged, never returned to the model, never leave the host.

[0.1.0]: https://github.com/ubercylon8/f0_sectools/releases/tag/v0.1.0
