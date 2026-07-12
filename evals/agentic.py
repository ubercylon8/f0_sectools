"""Multi-step (agentic) skill eval: can a small local model DRIVE a whole SKILL.md
procedure? Skill-adherence — the skill's Procedure is injected live — scored on a
dual metric: tool-coverage% (order-tolerant) + goal-reached (keyword check).

Deterministic per-scenario mock tools; local-only (needs Ollama), never CI. The
harness logic here is covered by evals/tests/test_agentic.py (offline, fake model).
"""
from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import yaml

from .run import AgentRun, ModelClient, combined_tool_schemas

EVALS = Path(__file__).resolve().parent
SKILLS_DIR = EVALS.parent / "skills"
SCENARIOS_DIR = EVALS / "scenarios"

_IDENTITY = (
    "You are a security-operations assistant driving read-only tools over the "
    "f0_sectools MCP servers. Follow the procedure below. Work one tool at a time: "
    "call a tool, read its result, then decide the next step. When you have enough "
    "to answer, reply with a final answer and no further tool call. Report only what "
    "the tools return."
)


def load_procedure(skill: str) -> str:
    """Return the text of the `## Procedure` section of skills/<skill>/SKILL.md
    (up to the next `## ` heading)."""
    text = (SKILLS_DIR / skill / "SKILL.md").read_text()
    m = re.search(r"^## Procedure\s*$", text, re.MULTILINE)
    if not m:
        return ""
    after = text[m.end():]
    end = after.find("\n## ")
    body = after if end == -1 else after[:end]
    return "## Procedure" + body.rstrip() + "\n"


def build_system_prompt(skill: str) -> str:
    return f"{_IDENTITY}\n\n{load_procedure(skill)}"


def make_mock_fn(scenario: dict) -> Callable[[str, dict], list]:
    mocks = scenario.get("mocks", {})

    def mock_fn(name: str, args: dict) -> list:
        return mocks.get(name, [{"note": f"no mock for {name}"}])

    return mock_fn


def score_run(scenario: dict, run: AgentRun) -> dict:
    required = scenario.get("required_tools", [])
    called = set(run.trajectory)
    coverage = (sum(1 for t in required if t in called) / len(required)) if required else 1.0
    answer = (run.final_answer or "").lower()
    goal = all(kw.lower() in answer for kw in scenario.get("goal_keywords", []))
    goal_reached = bool(goal) and run.error is None
    return {
        "coverage": coverage,
        "goal_reached": goal_reached,
        "passed": coverage == 1.0 and goal_reached,
        "trajectory": run.trajectory,
        "error": run.error,
    }


def load_scenario(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


async def run_scenario(client: ModelClient, scenario: dict) -> dict:
    """Run one scenario end-to-end and score it."""
    system = build_system_prompt(scenario["skill"])
    tools = await combined_tool_schemas()
    run = await client.run_agent(system, scenario["task"], tools, make_mock_fn(scenario))
    return score_run(scenario, run)
