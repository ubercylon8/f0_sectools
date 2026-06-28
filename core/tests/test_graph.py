import httpx
import pytest
import respx
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient, GraphError

CFG = PlatformConfig(tenant_id="t", client_id="c", client_secret="s")
TOKEN_URL = "https://login.microsoftonline.com/t/oauth2/v2.0/token"


def _token_route(router):
    router.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
    )


@pytest.mark.asyncio
async def test_get_all_follows_nextlink():
    base = "https://graph.microsoft.com/v1.0/security/incidents"
    with respx.mock as router:
        _token_route(router)
        # Two successive pages from the SAME endpoint: page 1 carries a nextLink,
        # page 2 ends the sequence. Modelling this as a response sequence on one
        # route (rather than two URL-distinct routes) avoids respx matching the
        # query-less route greedily for the follow-up request.
        router.get(base).mock(
            side_effect=[
                httpx.Response(
                    200,
                    json={"value": [{"id": "1"}], "@odata.nextLink": base + "?$skiptoken=abc"},
                ),
                httpx.Response(200, json={"value": [{"id": "2"}]}),
            ]
        )
        async with GraphClient(CFG) as gc:
            items = await gc.get_all("/security/incidents")
    assert [i["id"] for i in items] == ["1", "2"]


@pytest.mark.asyncio
async def test_get_raises_grapherror_on_403():
    with respx.mock as router:
        _token_route(router)
        router.get("https://graph.microsoft.com/v1.0/security/incidents").mock(
            return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}})
        )
        async with GraphClient(CFG) as gc:
            with pytest.raises(GraphError) as e:
                await gc.get("/security/incidents")
    assert e.value.status == 403
