"""Async Microsoft Graph client: token cache, pagination, 429/401 retry.

Ported from ProjectAchilles' MicrosoftGraphClient (backend/src/services/defender/
graph-client.ts): OAuth2 client-credentials grant, 300s token refresh margin,
``@odata.nextLink`` pagination, ``Retry-After`` backoff, one-shot 401 refresh.
Shared by the Defender and Entra servers (one app registration may serve both).
"""
from __future__ import annotations

import asyncio
import time

import httpx

from ..redaction.redact import redact_text
from .config import PlatformConfig

TOKEN_REFRESH_MARGIN_S = 300
MAX_RETRIES = 3


class GraphError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = redact_text(message)
        super().__init__(f"Graph HTTP {status}: {self.message}")


class GraphClient:
    def __init__(
        self, config: PlatformConfig, base_url: str = "https://graph.microsoft.com/v1.0"
    ) -> None:
        self._cfg = config
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(verify=config.verify_tls, timeout=60.0)
        self._token: str | None = None
        self._token_exp: float = 0.0

    async def __aenter__(self) -> GraphClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def get_token(self) -> str:
        now = time.time()
        if self._token and self._token_exp > now + TOKEN_REFRESH_MARGIN_S:
            return self._token
        url = f"https://login.microsoftonline.com/{self._cfg.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._cfg.client_id,
            "client_secret": self._cfg.client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }
        resp = await self._client.post(url, data=data)
        if resp.status_code != 200:
            raise GraphError(resp.status_code, "token request failed")
        payload = resp.json()
        self._token = payload["access_token"]
        self._token_exp = now + int(payload.get("expires_in", 3600))
        return self._token

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> dict:
        for attempt in range(MAX_RETRIES + 1):
            token = await self.get_token()
            headers = {"Authorization": f"Bearer {token}"}
            resp = await self._client.request(
                method, self._url(path), params=params, json=json_body, headers=headers
            )
            if resp.status_code == 401 and attempt == 0:
                self._token = None  # force refresh, retry once
                continue
            if resp.status_code == 429 and attempt < MAX_RETRIES:
                await asyncio.sleep(float(resp.headers.get("Retry-After", "1")))
                continue
            if resp.status_code // 100 != 2:
                try:
                    msg = resp.json().get("error", {}).get("message", "")
                except Exception:
                    msg = resp.text
                raise GraphError(resp.status_code, msg or "request failed")
            return resp.json() if resp.content else {}
        raise GraphError(429, "exceeded retry budget")

    async def get(self, path: str, params: dict | None = None) -> dict:
        return await self._request("GET", path, params=params)

    async def post(self, path: str, json_body: dict) -> dict:
        return await self._request("POST", path, json_body=json_body)

    async def get_all(self, path: str, params: dict | None = None) -> list[dict]:
        items: list[dict] = []
        page = await self._request("GET", path, params=params)
        items.extend(page.get("value", []))
        next_link = page.get("@odata.nextLink")
        while next_link:
            page = await self._request("GET", next_link)
            items.extend(page.get("value", []))
            next_link = page.get("@odata.nextLink")
        return items
