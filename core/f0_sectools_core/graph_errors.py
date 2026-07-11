"""Map Microsoft Graph errors to graceful findings.

Centralizes the status-code -> finding mapping so every tool degrades the same
way: a 403 names the missing permission, a sustained 429 reports throttling,
and a 502/503/504 gateway error reports transient unavailability. Anything
else returns None and the caller re-raises.
"""
from __future__ import annotations

from .auth.graph import GraphError
from .schema.findings import Finding


def map_graph_error(
    e: GraphError, source: str, permission: str, capability: str
) -> Finding | None:
    if e.status == 403:
        return Finding.permission_missing(source, permission, capability)
    if e.status == 429:
        return Finding.rate_limited(source, capability)
    if e.status in (502, 503, 504):
        return Finding.api_unavailable(source, capability, e.status)
    return None
