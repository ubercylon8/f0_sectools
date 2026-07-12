# f0-sectools-core

The shared foundation imported by every f0_sectools MCP server. **All
safety-critical and cross-cutting logic lives here — never in a server.**

| Module | Responsibility |
|--------|----------------|
| `schema/`     | The normalized findings schema and its validators. Every tool returns this. |
| `redaction/`  | Strips secrets, tokens, and raw PII from **all** output, including error paths. |
| `auth/`       | Per-platform `.env` loading and token refresh. Secrets never leave this layer. |
| `paging/`     | Pagination, truncation, and rate-limiting so payloads stay small-model-safe. |
| `smallmodel/` | Tool helpers: flat-argument builders, enum guards, argument validation. |
| `gating/`     | Gated write-action machinery (flag + confirmation token) and the local audit log. |
| `renderers/`  | Persona renderers (SOC analyst, security engineer, CISO, threat hunter, detection engineer). Public API: `render_finding` / `render_findings`. |

See [../CLAUDE.md](../CLAUDE.md) for the architectural rules these modules enforce.
