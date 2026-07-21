"""f0_sectools shared core.

The foundation imported by every f0_sectools MCP server. All safety-critical and
cross-cutting logic — the findings schema, redaction, auth, paging, small-model
helpers, gated-action machinery, and persona renderers — lives here so it is
enforced in one auditable place and cannot drift across platform servers.

See CLAUDE.md at the repository root for the rules these modules implement.
"""

__version__ = "0.2.0"
