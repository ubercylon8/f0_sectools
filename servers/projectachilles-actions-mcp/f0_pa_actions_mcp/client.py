"""Thin async client for the ProjectAchilles REST API (reads + gated writes).

Auth is a static `Authorization: Bearer pa_…` key. Writes additionally require
the key to be read-write scope — a read-only key produces HTTP 403, which the
tools map to a permission finding. Errors are raised as ProjectAchillesError
with a redacted message; the tools map them to graceful findings.
"""
from __future__ import annotations

from typing import Any

import httpx
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.redaction.redact import redact_text


class ProjectAchillesError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = redact_text(message)
        super().__init__(f"ProjectAchilles HTTP {status}: {self.message}")


class ProjectAchillesClient:
    def __init__(self, config: ProjectAchillesConfig) -> None:
        self.base_url = config.base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            verify=config.verify_tls,
            timeout=60.0,
            headers={"Authorization": f"Bearer {config.api_key}"},
        )

    async def __aenter__(self) -> ProjectAchillesClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        resp = await self._client.request(
            method, f"{self.base_url}/api{path}", params=params, json=json
        )
        if resp.status_code // 100 != 2:
            try:
                body = resp.json()
                msg = body.get("error") or body.get("message") or resp.text
            except Exception:
                msg = resp.text
            raise ProjectAchillesError(resp.status_code, str(msg) or "request failed")
        out = resp.json() if resp.content else {}
        return out if isinstance(out, dict) else {"data": out}

    async def get(
        self, path: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._request("GET", path, params=params)

    async def post(
        self, path: str, json: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._request("POST", path, json=json)

    async def patch(
        self, path: str, json: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._request("PATCH", path, json=json)
