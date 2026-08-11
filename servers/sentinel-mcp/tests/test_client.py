"""Contract tests for the Sentinel two-half client."""
from __future__ import annotations

import httpx
import pytest
from f0_sectools_core.auth.config import SentinelConfig
from f0_sectools_core.auth.graph import GraphError
from f0_sentinel_mcp.client import SentinelClient, rows_to_dicts


def _cfg(**over):
    base = dict(
        tenant_id="t", client_id="c", client_secret="s", workspace_id="ws",
        subscription_id="sub", resource_group="rg", workspace_name="name",
    )
    base.update(over)
    return SentinelConfig(**base)


def test_rows_to_dicts_maps_columns_onto_rows():
    body = {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [{"name": "DataType"}, {"name": "GB"}],
                "rows": [["CommonSecurityLog", 250.45], ["Syslog", 2.35]],
            }
        ]
    }
    assert rows_to_dicts(body) == [
        {"DataType": "CommonSecurityLog", "GB": 250.45},
        {"DataType": "Syslog", "GB": 2.35},
    ]


def test_rows_to_dicts_handles_empty_and_malformed():
    assert rows_to_dicts({}) == []
    assert rows_to_dicts({"tables": []}) == []
    assert rows_to_dicts({"tables": [{"columns": [], "rows": []}]}) == []


def test_rows_to_dicts_skips_non_list_rows_instead_of_raising():
    # A truncated or mangled response body can put a non-list entry (None, a
    # bare string, a dict) in "rows". zip() would raise TypeError on a
    # non-iterable and dict(zip(...)) on a string would silently produce
    # garbage — either way violates "malformed payload yields [], never
    # raises". Bad entries are skipped; good ones still come back.
    body = {
        "tables": [
            {
                "columns": [{"name": "a"}],
                "rows": [None, [1], "oops", {"a": 1}, [2]],
            }
        ]
    }
    assert rows_to_dicts(body) == [{"a": 1}, {"a": 2}]


async def test_query_posts_body_and_returns_dicts(monkeypatch):
    captured = {}

    async def fake_post(path, json_body):
        captured["path"] = path
        captured["body"] = json_body
        return {"tables": [{"columns": [{"name": "n"}], "rows": [[1]]}]}

    client = SentinelClient(_cfg())
    monkeypatch.setattr(client._logs, "post", fake_post)
    rows = await client.query("Usage | take 1", "P30D")

    assert rows == [{"n": 1}]
    assert captured["path"] == "/workspaces/ws/query"
    assert captured["body"] == {"query": "Usage | take 1", "timespan": "P30D"}


async def test_arm_list_builds_securityinsights_path(monkeypatch):
    captured = {}

    async def fake_get(path, params=None):
        captured["path"] = path
        captured["params"] = params
        return {"value": [{"name": "rule-1"}]}

    client = SentinelClient(_cfg())
    monkeypatch.setattr(client._arm, "get", fake_get)
    out = await client.arm_list("alertRules")

    assert out == [{"name": "rule-1"}]
    assert captured["path"] == (
        "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights"
        "/workspaces/name/providers/Microsoft.SecurityInsights/alertRules"
    )
    assert captured["params"] == {"api-version": "2024-09-01"}


async def test_arm_list_without_arm_config_raises_valueerror():
    client = SentinelClient(_cfg(subscription_id=None))
    assert client.has_arm is False
    with pytest.raises(ValueError, match="ARM coordinates"):
        await client.arm_list("alertRules")


def test_client_exposes_retention_days():
    assert SentinelClient(_cfg()).retention_days == 30
    assert SentinelClient(_cfg(retention_days=90)).retention_days == 90


async def test_query_converts_transport_timeout_to_graph_error_504(monkeypatch):
    # A runaway scan over a very large table blows httpx's timeout rather than
    # returning HTTP 504. If that escapes as httpx.TimeoutException, every tool
    # re-raises and the "never raise" rule breaks exactly when it matters most.
    # Converting it here means errors.py's existing 504 branch handles it.
    async def fake_post(path, json_body):
        raise httpx.ReadTimeout("timed out")

    client = SentinelClient(_cfg())
    monkeypatch.setattr(client._logs, "post", fake_post)
    with pytest.raises(GraphError) as exc:
        await client.query("CommonSecurityLog | take 1", "PT24H")
    assert exc.value.status == 504


async def test_arm_list_converts_transport_timeout_too(monkeypatch):
    async def fake_get(path, params=None):
        raise httpx.ConnectTimeout("timed out")

    client = SentinelClient(_cfg())
    monkeypatch.setattr(client._arm, "get", fake_get)
    with pytest.raises(GraphError) as exc:
        await client.arm_list("alertRules")
    assert exc.value.status == 504
