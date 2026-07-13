"""Thin async client for the Tenable Vulnerability Management API.

Auth is a static ``X-ApiKeys: accessKey=<>;secretKey=<>`` header. Errors are
raised as TenableError with a redacted message; the tools map them to graceful
findings.
"""
from __future__ import annotations

from typing import Any

import httpx
from f0_sectools_core.auth.config import TenableConfig
from f0_sectools_core.redaction.redact import redact_text


class TenableError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = redact_text(message)
        super().__init__(f"Tenable HTTP {status}: {self.message}")


class TenableClient:
    def __init__(self, config: TenableConfig) -> None:
        self.base_url = config.base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            verify=config.verify_tls,
            timeout=60.0,
            headers={
                "X-ApiKeys": f"accessKey={config.access_key};secretKey={config.secret_key}",
                "Accept": "application/json",
            },
        )

    async def __aenter__(self) -> TenableClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = await self._client.get(f"{self.base_url}{path}", params=params)
        if resp.status_code // 100 != 2:
            try:
                body = resp.json()
                msg = body.get("error") or body.get("message") or resp.text
            except Exception:
                msg = resp.text
            raise TenableError(resp.status_code, str(msg) or "request failed")
        return resp.json() if resp.content else {}
