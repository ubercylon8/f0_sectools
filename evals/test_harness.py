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
    SuiteUnusable,
    ToolCall,
    assert_suite_usable,
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


# ---------- a serving problem must never be published as a score ----------

def _report(no_call_rate: float, n: int = 8) -> dict:
    return {
        "tasks": [{"prompt": f"p{i}", "calls": [None]} for i in range(n)],
        "overall_tool_rate": 0.0,
        "overall_args_rate": 0.0,
        "no_call_rate": no_call_rate,
        "schema_kb": 32.0,
        "tool_count": 51,
    }


def test_a_suite_with_no_tool_calls_at_all_is_unusable_not_zero():
    # Observed 2026-07-26: four models scored 0%/0% on the 51-tool composition
    # purely because Ollama served them with its 4096-token default num_ctx
    # while the schema alone is ~32 KB. Scoring that as 0% would publish a false
    # claim about the exact thesis the scorecard exists to test.
    with pytest.raises(SuiteUnusable) as exc:
        assert_suite_usable(_report(1.0), "gemma4:e4b")
    msg = str(exc.value)
    assert "gemma4:e4b" in msg
    assert "32.0 KB" in msg and "51" in msg      # actionable, not just "failed"
    assert "num_ctx" in msg                       # names the fix


def test_a_model_that_calls_the_wrong_tool_still_scores():
    # The distinction that matters: a model bad at SELECTION still calls
    # something. Only a model calling nothing at all signals a setup problem.
    assert_suite_usable(_report(0.0), "m")
    assert_suite_usable(_report(0.99), "m")   # even near-total silence scores


@pytest.mark.asyncio
async def test_run_suite_reports_the_silence_and_the_schema_size():
    class Mute:
        async def call(self, prompt, tools):
            return None

    tools = [{"type": "function", "function": {"name": "t", "parameters": {}}}]
    tasks = [{"prompt": "p", "expect_tool": "t"}, {"prompt": "q", "expect_tool": "t"}]
    rep = await run_suite(tools, tasks, Mute(), runs=1)
    assert rep["no_call_rate"] == 1.0
    assert rep["tool_count"] == 1
    assert rep["schema_kb"] > 0


@pytest.mark.asyncio
async def test_a_partially_silent_suite_is_still_scored():
    class Half:
        def __init__(self):
            self.n = 0

        async def call(self, prompt, tools):
            self.n += 1
            return ToolCall(name="t", args={}) if self.n % 2 else None

    tools = [{"type": "function", "function": {"name": "t", "parameters": {}}}]
    tasks = [{"prompt": f"p{i}", "expect_tool": "t"} for i in range(4)]
    rep = await run_suite(tools, tasks, Half(), runs=1)
    assert 0.0 < rep["no_call_rate"] < 1.0
    assert_suite_usable(rep, "m")  # must not raise
