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
}


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]


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

    async def call(self, prompt: str, tools: list[dict]) -> ToolCall | None:
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "tools": tools,
            "tool_choice": "auto",
            "temperature": 0,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        resp = await self._client.post(
            f"{self.base_url}/chat/completions", json=body, headers=headers
        )
        resp.raise_for_status()
        message = resp.json()["choices"][0]["message"]
        calls = message.get("tool_calls") or []
        if not calls:
            return None
        fn = calls[0]["function"]
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except (ValueError, TypeError):
            args = {}
        return ToolCall(name=fn["name"], args=args if isinstance(args, dict) else {})


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


async def _amain(args: argparse.Namespace) -> None:
    tasks = load_tasks(args.server)
    tools = await server_tool_schemas(args.server)
    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    async with ModelClient(args.base_url, args.model, api_key) as client:
        report = await run_suite(tools, tasks, client, runs=args.runs)
    print(format_report(args.server, args.model, report))


def main() -> None:
    p = argparse.ArgumentParser(description="f0_sectools small-model tool-calling eval")
    p.add_argument("--server", required=True, choices=sorted(SERVER_MODULES))
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
