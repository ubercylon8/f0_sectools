"""Small-model tool-calling eval harness.

Replays a server's eval task set (evals/<server>/tasks.yaml) against a locally
served, OpenAI-compatible model (vLLM / llama.cpp) and scores how reliably the
model selects the right tool and fills the right arguments. This is the
measurement behind the repo's promise: "tools small models can actually drive."

Usage (from the repo root, with a model served locally):

    uv run python -m evals.run --server defender \\
        --base-url http://localhost:8000/v1 --model openai/gpt-oss-20b --runs 3

A tool that scores poorly means its schema is too hard for the model — simplify
the tool, don't lower the bar.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

EVALS = Path(__file__).parent

# eval directory name -> server module exposing `mcp`
SERVER_MODULES = {
    "defender": "f0_defender_mcp.server",
    "entra": "f0_entra_mcp.server",
    "limacharlie": "f0_limacharlie_mcp.server",
    "projectachilles": "f0_projectachilles_mcp.server",
    "intune": "f0_intune_mcp.server",
}


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]


@dataclass
class AgentRun:
    """The outcome of a multi-step run: the ordered tool names called, the model's
    final answer, how many turns it took, and an error string if the loop failed
    or hit max_steps."""
    trajectory: list[str]
    final_answer: str
    steps: int
    error: str | None = None


def load_tasks(server: str) -> list[dict]:
    return yaml.safe_load((EVALS / server / "tasks.yaml").read_text())


def build_openai_tools(mcp_tools: list[Any]) -> list[dict]:
    """Convert MCP Tool objects to OpenAI function-tool schemas."""
    out: list[dict] = []
    for t in mcp_tools:
        out.append(
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": getattr(t, "description", "") or "",
                    "parameters": getattr(t, "inputSchema", None)
                    or {"type": "object", "properties": {}},
                },
            }
        )
    return out


async def server_tool_schemas(server: str) -> list[dict]:
    module = importlib.import_module(SERVER_MODULES[server])
    return build_openai_tools(await module.mcp.list_tools())


async def combined_tool_schemas() -> list[dict]:
    """Union of every server's tool schemas — the registry an operator sees with
    all servers registered at once. Raises if two servers expose the same tool
    name (would make the OpenAI tool list ambiguous)."""
    out: list[dict] = []
    seen: set[str] = set()
    for server in sorted(SERVER_MODULES):
        for schema in await server_tool_schemas(server):
            name = schema["function"]["name"]
            if name in seen:
                raise ValueError(f"tool name collision across servers: {name!r}")
            seen.add(name)
            out.append(schema)
    return out


def combined_tasks() -> list[dict]:
    """Every per-server task tagged with its origin server, plus the cross-platform
    routing probes. This is the task set for the combined 28-tool registry."""
    tasks: list[dict] = []
    for server in sorted(SERVER_MODULES):
        for t in load_tasks(server):
            tasks.append({**t, "origin": server})
    probes_path = EVALS / "combined" / "probes.yaml"
    if probes_path.exists():
        for p in yaml.safe_load(probes_path.read_text()) or []:
            tasks.append(dict(p))  # probes already carry `origin`
    return tasks


def aggregate_by_origin(tasks: list[dict], report: dict) -> dict:
    """Group the suite report's per-task rows by their `origin` server. Relies on
    run_suite preserving task order. For each origin: mean tool/args rate, count,
    and which wrong tools its prompts were misrouted to."""
    groups: dict[str, dict] = {}
    for task, row in zip(tasks, report["tasks"], strict=True):
        origin = task.get("origin", "unknown")
        g = groups.setdefault(origin, {"tool": [], "args": [], "misroutes": {}})
        g["tool"].append(row["tool_rate"])
        g["args"].append(row["args_rate"])
        if row["tool_rate"] < 1.0:
            for called in row.get("calls", []):
                if called and called != task["expect_tool"]:
                    g["misroutes"][called] = g["misroutes"].get(called, 0) + 1
    out: dict[str, dict] = {}
    for origin, g in groups.items():
        n = len(g["tool"]) or 1
        out[origin] = {
            "tool_rate": sum(g["tool"]) / n,
            "args_rate": sum(g["args"]) / n,
            "n": len(g["tool"]),
            "misroutes": g["misroutes"],
        }
    return out


class ModelClient:
    """Minimal OpenAI-compatible chat client for tool-calling evals."""

    def __init__(self, base_url: str, model: str, api_key: str | None = None,
                 timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key or "not-needed"
        self._client = httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self) -> ModelClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def _post_chat(self, messages: list[dict], tools: list[dict]) -> dict:
        """POST one chat turn and return the assistant `message` dict. Retries
        transient blips (connection drops, read timeouts, 5xx) so a single hiccup
        over a long sequential sweep doesn't crash the run; a 4xx raises at once."""
        body = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": 0,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        url = f"{self.base_url}/chat/completions"
        last_exc: BaseException | None = None
        attempts = 3
        for attempt in range(attempts):
            try:
                resp = await self._client.post(url, json=body, headers=headers)
                if resp.status_code >= 500:
                    last_exc = httpx.HTTPStatusError(
                        f"server error {resp.status_code}", request=resp.request, response=resp
                    )
                    if attempt < attempts - 1:
                        await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                resp.raise_for_status()
            except httpx.TransportError as e:
                last_exc = e
                if attempt < attempts - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))
                continue
            return resp.json()["choices"][0]["message"]
        if last_exc is None:  # pragma: no cover - unreachable
            raise RuntimeError("model call failed with no captured error")
        raise last_exc

    async def call(self, prompt: str, tools: list[dict]) -> ToolCall | None:
        message = await self._post_chat([{"role": "user", "content": prompt}], tools)
        calls = message.get("tool_calls") or []
        if not calls:
            return None
        fn = calls[0]["function"]
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except (ValueError, TypeError):
            args = {}
        return ToolCall(name=fn["name"], args=args if isinstance(args, dict) else {})

    async def run_agent(
        self,
        system: str,
        user: str,
        tools: list[dict],
        mock_fn: Callable[[str, dict], list],
        max_steps: int = 12,
    ) -> AgentRun:
        """Drive a multi-step tool-calling loop against deterministic mock tool
        results. Returns the ordered trajectory of tool names, the final answer,
        step count, and an error (transport failure or max_steps) if any."""
        messages: list[dict] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        trajectory: list[str] = []
        for step in range(max_steps):
            try:
                message = await self._post_chat(messages, tools)
            except Exception as e:  # noqa: BLE001 — record and stop, don't crash the sweep
                return AgentRun(trajectory, "", step, error=f"{type(e).__name__}: {e}")
            calls = message.get("tool_calls") or []
            if not calls:
                return AgentRun(trajectory, message.get("content") or "", step, None)
            messages.append({
                "role": "assistant",
                "content": message.get("content") or "",
                "tool_calls": calls,
            })
            for c in calls:
                fn = c["function"]
                name = fn["name"]
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                    if not isinstance(args, dict):
                        args = {}
                except (ValueError, TypeError):
                    args = {}
                trajectory.append(name)
                result = mock_fn(name, args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": c.get("id", name),
                    "content": json.dumps(result, default=str),
                })
        return AgentRun(trajectory, "", max_steps, error="max_steps reached")


def _args_match(task: dict, args: dict) -> bool:
    for k, v in (task.get("expect_args") or {}).items():
        if str(args.get(k)) != str(v):
            return False
    for k, v in (task.get("expect_args_contains") or {}).items():
        if str(v).lower() not in str(args.get(k, "")).lower():
            return False
    return True


def score_task(task: dict, call: ToolCall | None) -> dict:
    """Score one model response. args_correct implies tool_correct."""
    if call is None:
        return {"tool_correct": False, "args_correct": False, "called": None}
    tool_ok = call.name == task["expect_tool"]
    args_ok = tool_ok and _args_match(task, call.args)
    return {"tool_correct": tool_ok, "args_correct": args_ok, "called": call.name}


async def run_suite(
    tools: list[dict], tasks: list[dict], client: ModelClient, runs: int = 1
) -> dict:
    """Run every task `runs` times; aggregate per-task and overall rates."""
    task_rows: list[dict] = []
    for task in tasks:
        attempts = []
        for _ in range(runs):
            call = await client.call(task["prompt"], tools)
            attempts.append(score_task(task, call))
        n = len(attempts)
        task_rows.append(
            {
                "prompt": task["prompt"],
                "expect_tool": task["expect_tool"],
                "tool_rate": sum(a["tool_correct"] for a in attempts) / n,
                "args_rate": sum(a["args_correct"] for a in attempts) / n,
                "runs": n,
                "calls": [a["called"] for a in attempts],
            }
        )
    total = len(task_rows) or 1
    return {
        "tasks": task_rows,
        "overall_tool_rate": sum(r["tool_rate"] for r in task_rows) / total,
        "overall_args_rate": sum(r["args_rate"] for r in task_rows) / total,
    }


def format_report(server: str, model: str, report: dict) -> str:
    lines = [f"\nEval: {server} server  x  {model}", "-" * 72]
    for r in report["tasks"]:
        lines.append(
            f"  tool {r['tool_rate']:5.0%}  args {r['args_rate']:5.0%}  "
            f"[{r['expect_tool']}]  {r['prompt'][:42]}"
        )
    lines.append("-" * 72)
    lines.append(
        f"  OVERALL  tool-selection {report['overall_tool_rate']:.0%}  "
        f"argument-filling {report['overall_args_rate']:.0%}"
    )
    return "\n".join(lines)


def format_combined_report(model: str, report: dict, origin_agg: dict) -> str:
    lines = [f"\nCombined eval (all 28 tools)  x  {model}", "-" * 72]
    for origin in sorted(origin_agg):
        g = origin_agg[origin]
        mis = ", ".join(f"{k}x{v}" for k, v in sorted(g["misroutes"].items())) or "-"
        lines.append(
            f"  {origin:16} tool {g['tool_rate']:5.0%}  args {g['args_rate']:5.0%}  "
            f"(n={g['n']})  misrouted-> {mis}"
        )
    lines.append("-" * 72)
    lines.append(
        f"  OVERALL  tool-selection {report['overall_tool_rate']:.0%}  "
        f"argument-filling {report['overall_args_rate']:.0%}"
    )
    return "\n".join(lines)


async def _amain(args: argparse.Namespace) -> None:
    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if args.server == "all":
        tools = await combined_tool_schemas()
        tasks = combined_tasks()
    else:
        tools = await server_tool_schemas(args.server)
        tasks = load_tasks(args.server)
    async with ModelClient(args.base_url, args.model, api_key) as client:
        report = await run_suite(tools, tasks, client, runs=args.runs)
    if args.server == "all":
        print(format_combined_report(args.model, report, aggregate_by_origin(tasks, report)))
    else:
        print(format_report(args.server, args.model, report))


def main() -> None:
    p = argparse.ArgumentParser(description="f0_sectools small-model tool-calling eval")
    p.add_argument("--server", required=True, choices=[*sorted(SERVER_MODULES), "all"])
    p.add_argument(
        "--base-url", required=True, help="OpenAI-compatible base URL (e.g. http://localhost:8000/v1)"
    )
    p.add_argument("--model", required=True, help="model id served locally")
    p.add_argument(
        "--api-key", default=None, help="optional; defaults to OPENAI_API_KEY env or unused"
    )
    p.add_argument("--runs", type=int, default=1, help="attempts per task (for success rate)")
    asyncio.run(_amain(p.parse_args()))


if __name__ == "__main__":
    main()
