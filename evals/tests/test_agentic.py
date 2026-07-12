"""Offline contract test for the agentic (multi-step) eval harness. No Ollama."""
from __future__ import annotations

import pytest

from evals.run import AgentRun, ModelClient


class FakeModelClient(ModelClient):
    """A ModelClient whose _post_chat replays a scripted list of assistant messages
    instead of hitting the network. Each entry is an OpenAI `message` dict."""

    def __init__(self, scripted: list[dict]) -> None:
        super().__init__("http://fake/v1", "fake-model")
        self._scripted = list(scripted)

    async def _post_chat(self, messages, tools):  # type: ignore[override]
        return self._scripted.pop(0)


def _tool_msg(name: str, args: str = "{}") -> dict:
    return {"content": "", "tool_calls": [
        {"id": f"c_{name}", "function": {"name": name, "arguments": args}}]}


def _final(text: str) -> dict:
    return {"content": text, "tool_calls": []}


@pytest.mark.asyncio
async def test_run_agent_captures_trajectory_and_feeds_mocks():
    calls_seen = []

    def mock_fn(name, args):
        calls_seen.append(name)
        return [{"note": f"result for {name}"}]

    client = FakeModelClient([_tool_msg("list_incidents"),
                              _tool_msg("get_sensor"),
                              _final("web-01 shows T1110; user is risky.")])
    async with client:
        run = await client.run_agent("SYS", "triage it", tools=[], mock_fn=mock_fn)

    assert isinstance(run, AgentRun)
    assert run.trajectory == ["list_incidents", "get_sensor"]
    assert calls_seen == ["list_incidents", "get_sensor"]  # mocks were invoked
    assert "web-01" in run.final_answer
    assert run.error is None


@pytest.mark.asyncio
async def test_run_agent_halts_at_max_steps():
    # a model that never stops calling tools
    client = FakeModelClient([_tool_msg("x")] * 20)
    async with client:
        run = await client.run_agent("SYS", "go", tools=[], mock_fn=lambda n, a: [{}], max_steps=3)
    assert run.error == "max_steps reached"
    assert len(run.trajectory) == 3
