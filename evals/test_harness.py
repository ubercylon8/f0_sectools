"""Tests for the eval harness — scoring, schema conversion, and the model client.

These run with NO local model: the OpenAI-compatible endpoint is mocked, and the
suite runner is exercised with a fake client.
"""
from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from evals.run import (
    ModelClient,
    ToolCall,
    build_openai_tools,
    run_suite,
    score_task,
)


@dataclass
class _FakeTool:
    name: str
    description: str
    inputSchema: dict


def test_build_openai_tools_shape():
    tools = build_openai_tools(
        [_FakeTool("list_incidents", "List incidents", {"type": "object", "properties": {}})]
    )
    assert tools[0]["type"] == "function"
    assert tools[0]["function"]["name"] == "list_incidents"
    assert tools[0]["function"]["parameters"]["type"] == "object"


def test_score_task_tool_and_args():
    task = {"prompt": "x", "expect_tool": "list_incidents", "expect_args": {"severity_min": "high"}}
    good = score_task(task, ToolCall("list_incidents", {"severity_min": "high"}))
    assert good["tool_correct"] and good["args_correct"]

    wrong_tool = score_task(task, ToolCall("list_alerts", {"severity_min": "high"}))
    assert not wrong_tool["tool_correct"] and not wrong_tool["args_correct"]

    wrong_args = score_task(task, ToolCall("list_incidents", {"severity_min": "low"}))
    assert wrong_args["tool_correct"] and not wrong_args["args_correct"]


def test_score_task_contains_and_no_call():
    task = {"prompt": "x", "expect_tool": "run_hunting_query",
            "expect_args_contains": {"kql": "DeviceProcessEvents"}}
    hit = score_task(task, ToolCall("run_hunting_query", {"kql": "DeviceProcessEvents | take 5"}))
    assert hit["args_correct"]
    miss = score_task(task, ToolCall("run_hunting_query", {"kql": "DeviceLogonEvents"}))
    assert miss["tool_correct"] and not miss["args_correct"]
    assert score_task(task, None) == {"tool_correct": False, "args_correct": False, "called": None}


@pytest.mark.asyncio
async def test_model_client_parses_tool_call():
    with respx.mock as router:
        router.post("http://local/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"tool_calls": [
                    {"function": {"name": "list_incidents",
                                  "arguments": '{"severity_min": "high"}'}}
                ]}}]},
            )
        )
        async with ModelClient("http://local/v1", "test-model") as client:
            call = await client.call("show high incidents", tools=[])
    assert call.name == "list_incidents"
    assert call.args == {"severity_min": "high"}


_OK = httpx.Response(200, json={"choices": [{"message": {"tool_calls": [
    {"function": {"name": "list_incidents", "arguments": "{}"}}]}}]})


@pytest.mark.asyncio
async def test_model_client_retries_transient_transport_error(monkeypatch):
    # A transient connection blip (common over a long sequential sweep) must be
    # retried, not crash the whole run.
    monkeypatch.setattr("evals.run.asyncio.sleep", AsyncMock())
    with respx.mock as router:
        router.post("http://local/v1/chat/completions").mock(
            side_effect=[httpx.ConnectError("transient blip"), _OK]
        )
        async with ModelClient("http://local/v1", "m", timeout=1.0) as client:
            call = await client.call("x", tools=[])
    assert call.name == "list_incidents"


@pytest.mark.asyncio
async def test_model_client_retries_5xx_then_succeeds(monkeypatch):
    # A 5xx (Ollama overloaded) is retried like a transport blip.
    monkeypatch.setattr("evals.run.asyncio.sleep", AsyncMock())
    with respx.mock as router:
        router.post("http://local/v1/chat/completions").mock(
            side_effect=[httpx.Response(503, json={"error": "overloaded"}), _OK]
        )
        async with ModelClient("http://local/v1", "m", timeout=1.0) as client:
            call = await client.call("x", tools=[])
    assert call.name == "list_incidents"


@pytest.mark.asyncio
async def test_model_client_4xx_raises_immediately_without_retry(monkeypatch):
    # A 4xx is a real client error — raise on the first attempt, no retry, no sleep.
    sleep_mock = AsyncMock()
    monkeypatch.setattr("evals.run.asyncio.sleep", sleep_mock)
    with respx.mock as router:
        route = router.post("http://local/v1/chat/completions").mock(
            return_value=httpx.Response(400, json={"error": "bad request"})
        )
        async with ModelClient("http://local/v1", "m", timeout=1.0) as client:
            with pytest.raises(httpx.HTTPStatusError):
                await client.call("x", tools=[])
    assert route.call_count == 1, "4xx must not be retried"
    sleep_mock.assert_not_awaited()  # 4xx must not back off


@pytest.mark.asyncio
async def test_model_client_raises_after_exhausting_retries(monkeypatch):
    monkeypatch.setattr("evals.run.asyncio.sleep", AsyncMock())
    with respx.mock as router:
        router.post("http://local/v1/chat/completions").mock(
            side_effect=httpx.ConnectError("always down")
        )
        async with ModelClient("http://local/v1", "m", timeout=1.0) as client:
            with pytest.raises(httpx.TransportError):
                await client.call("x", tools=[])


@pytest.mark.asyncio
async def test_model_client_no_tool_call_returns_none():
    with respx.mock as router:
        router.post("http://local/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
        )
        async with ModelClient("http://local/v1", "test-model") as client:
            call = await client.call("hello", tools=[])
    assert call is None


@pytest.mark.asyncio
async def test_run_suite_aggregates_rates():
    tasks = [
        {"prompt": "a", "expect_tool": "list_incidents", "expect_args": {"severity_min": "high"}},
        {"prompt": "b", "expect_tool": "get_secure_score"},
    ]

    class _FakeClient:
        async def call(self, prompt, tools):
            if prompt == "a":
                return ToolCall("list_incidents", {"severity_min": "high"})  # fully correct
            return ToolCall("list_alerts", {})  # wrong tool for task b

    report = await run_suite([], tasks, _FakeClient(), runs=2)
    assert report["overall_tool_rate"] == 0.5  # 1 of 2 tasks correct tool
    assert report["overall_args_rate"] == 0.5
    assert report["tasks"][0]["tool_rate"] == 1.0
    assert report["tasks"][1]["tool_rate"] == 0.0
