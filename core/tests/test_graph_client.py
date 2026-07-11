import httpx
import pytest
import respx
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient

CFG = PlatformConfig(tenant_id="t", client_id="c", client_secret="s")
TOKEN_URL = "https://login.microsoftonline.com/t/oauth2/v2.0/token"


@pytest.mark.asyncio
async def test_get_token_uses_custom_scope():
    with respx.mock as router:
        route = router.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        )
        sec_scope = "https://api.security.microsoft.com/.default"
        async with GraphClient(
            CFG,
            base_url="https://api.security.microsoft.com/api",
            scope=sec_scope,
        ) as gc:
            await gc.get_token()
        sent = route.calls[0].request
        # scope is URL-encoded in the form body
        assert "api.security.microsoft.com" in httpx.QueryParams(sent.content.decode())["scope"]


@pytest.mark.asyncio
async def test_get_token_defaults_to_graph_scope():
    with respx.mock as router:
        route = router.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        )
        async with GraphClient(CFG) as gc:
            await gc.get_token()
        sent = route.calls[0].request
        assert "graph.microsoft.com" in httpx.QueryParams(sent.content.decode())["scope"]
