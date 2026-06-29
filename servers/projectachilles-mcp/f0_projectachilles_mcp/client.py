"""Thin async client for the ProjectAchilles REST API.

Auth is a static `Authorization: Bearer pa_…` key (the org is embedded in it).
Errors are raised as ProjectAchillesError with a redacted message; the tools map
them to graceful findings.
"""
from __future__ import annotations

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

    async def get(self, path: str, params: dict | None = None) -> dict:
        resp = await self._client.get(f"{self.base_url}/api{path}", params=params)
        if resp.status_code // 100 != 2:
            try:
                body = resp.json()
                msg = body.get("error") or body.get("message") or resp.text
            except Exception:
                msg = resp.text
            raise ProjectAchillesError(resp.status_code, str(msg) or "request failed")
        return resp.json() if resp.content else {}
