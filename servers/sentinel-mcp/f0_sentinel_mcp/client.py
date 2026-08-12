"""Thin async client for Microsoft Sentinel's two API surfaces.

Sentinel is two APIs, not one, and they differ in host, token audience, and
Azure RBAC:

  * logs    -> https://api.loganalytics.azure.com/v1  (Log Analytics Reader)
  * objects -> https://management.azure.com           (Microsoft Sentinel Reader)

Both are plain OAuth2 client-credentials, so both are driven by core's
``GraphClient`` with a different ``base_url``/``scope`` — no core change was
needed. The two halves fail independently: a tenant may grant one role and not
the other, and the tools report that per-half rather than as a dead server.
"""
from __future__ import annotations

from typing import Any

import httpx
from f0_sectools_core.auth.config import PlatformConfig, SentinelConfig
from f0_sectools_core.auth.graph import GraphClient, GraphError

LOGS_BASE = "https://api.loganalytics.azure.com/v1"
LOGS_SCOPE = "https://api.loganalytics.io/.default"
ARM_BASE = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
ARM_API_VERSION = "2024-09-01"


def rows_to_dicts(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a Log Analytics ``{tables:[{columns,rows}]}`` payload to dicts.

    The query API returns columns and rows separately; every tool wants dicts.
    Defensive throughout — a malformed or empty payload yields an empty list
    rather than raising, because a query that matched nothing and a query that
    returned an odd shape are both "no findings", not "crash the agent".
    """
    tables = body.get("tables") or []
    if not tables:
        return []
    first = tables[0] or {}
    cols = [str(c.get("name", "")) for c in (first.get("columns") or [])]
    if not cols:
        return []
    return [
        dict(zip(cols, row, strict=False))
        for row in (first.get("rows") or [])
        if isinstance(row, list)
    ]


class SentinelClient:
    def __init__(self, config: SentinelConfig) -> None:
        self._cfg = config
        platform = PlatformConfig(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret,
            verify_tls=config.verify_tls,
        )
        self._logs = GraphClient(platform, base_url=LOGS_BASE, scope=LOGS_SCOPE)
        self._arm = GraphClient(platform, base_url=ARM_BASE, scope=ARM_SCOPE)

    @property
    def retention_days(self) -> int:
        return self._cfg.retention_days

    @property
    def has_arm(self) -> bool:
        return self._cfg.has_arm

    @property
    def workspace_id(self) -> str:
        return self._cfg.workspace_id

    async def __aenter__(self) -> SentinelClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._logs.__aexit__()
        await self._arm.__aexit__()

    async def query(self, kql: str, timespan: str) -> list[dict[str, Any]]:
        """Run a KQL query against the workspace and return rows as dicts."""
        try:
            body = await self._logs.post(
                f"/workspaces/{self._cfg.workspace_id}/query",
                {"query": kql, "timespan": timespan},
            )
        except httpx.TimeoutException as e:
            # A scan too large to finish inside the transport timeout is
            # operationally a gateway timeout. Normalizing it here keeps the
            # "every failure is a finding" rule intact without teaching seven
            # tools about transport exceptions.
            raise GraphError(504, "query exceeded the request timeout") from e
        return rows_to_dicts(body)

    async def arm_list(self, resource: str) -> list[dict[str, Any]]:
        """List a Microsoft.SecurityInsights child resource (e.g. ``alertRules``)."""
        if not self._cfg.has_arm:
            raise ValueError(
                "ARM coordinates not configured (SENTINEL_SUBSCRIPTION_ID, "
                "SENTINEL_RESOURCE_GROUP, SENTINEL_WORKSPACE_NAME)"
            )
        path = (
            f"/subscriptions/{self._cfg.subscription_id}"
            f"/resourceGroups/{self._cfg.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self._cfg.workspace_name}"
            f"/providers/Microsoft.SecurityInsights/{resource}"
        )
        try:
            body = await self._arm.get(path, params={"api-version": ARM_API_VERSION})
        except httpx.TimeoutException as e:
            raise GraphError(504, "request exceeded the request timeout") from e
        value = body.get("value")
        return list(value) if isinstance(value, list) else []
