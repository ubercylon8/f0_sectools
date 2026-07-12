# Agentic Skill Eval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a multi-step eval harness (`evals/agentic.py`) that measures whether a small local model can drive a whole `SKILL.md` procedure — the right tool *sequence*, results fed forward, correct conclusion — alongside the existing single-turn scorecard.

**Architecture:** Reuse `evals/run.py`'s `ModelClient`, adding a multi-turn `run_agent` loop. `agentic.py` builds a skill-adherence prompt (the skill's live `## Procedure` + task), runs the loop against deterministic per-scenario mocks, and scores a dual metric (tool-coverage% + goal-reached). `agentic_scorecard.py` renders a skill×model matrix. Harness logic is covered by an offline contract test (fake model); the real matrix is produced by running against Ollama (local, never CI).

**Tech Stack:** Python 3.11+, `httpx` (existing), `pyyaml`, `pytest`. No new deps.

## Global Constraints

- Skill-adherence: the model receives the skill's `## Procedure`, read **live** from `skills/<skill>/SKILL.md` at run time (never a stale copy).
- Dual metric: **coverage%** = `|required_tools ∩ tools_called| / |required_tools|` (order-tolerant); **goal-reached** = every `goal_keywords` entry is a case-insensitive substring of the final answer. Pass = coverage 100% AND goal AND no error.
- Deterministic mocks keyed by **tool name** (v1); a tool with no mock returns `[{"note": "no mock for <tool>"}]` and the run continues.
- Reuse `ModelClient`; refactor its HTTP-post-with-retry into one shared helper (`_post_chat`) used by both `call` and `run_agent` — no behavior change to `call`.
- The model sees the **combined 28-tool registry** (`combined_tool_schemas()`) in every scenario (realistic; also tests selection among many).
- `max_steps` bounds the loop (default 8) so a runaway model can't spin forever.
- Local-only, never in CI (needs Ollama). The offline harness test IS CI-safe.
- Both evals read the model set from `evals/models.yaml`; **Ministral 3 is removed** from it.
- `uv run pytest` and `ruff check .` stay green.

---

### Task 1: `ModelClient.run_agent` multi-turn loop + `AgentRun`

**Files:**
- Modify: `evals/run.py`
- Test: `evals/tests/test_agentic.py` (create)

**Interfaces:**
- Consumes: existing `ModelClient` httpx client + retry logic.
- Produces:
  - `@dataclass AgentRun(trajectory: list[str], final_answer: str, steps: int, error: str | None = None)`
  - `ModelClient._post_chat(self, messages: list[dict], tools: list[dict]) -> dict` — one chat turn with retry, returns the assistant message dict.
  - `ModelClient.run_agent(self, system: str, user: str, tools: list[dict], mock_fn: Callable[[str, dict], list], max_steps: int = 8) -> AgentRun`

- [ ] **Step 1: Write the failing test**

Create `evals/tests/test_agentic.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest evals/tests/test_agentic.py -q`
Expected: FAIL — `ImportError: cannot import name 'AgentRun'` (and `run_agent`/`_post_chat` do not exist).

- [ ] **Step 3: Implement in `evals/run.py`**

Add the import (top of file, with the others):

```python
from collections.abc import Callable
from dataclasses import dataclass
```
(If `dataclass` / `Callable` are already imported, don't duplicate.)

Add the dataclass near `ToolCall`:

```python
@dataclass
class AgentRun:
    """The outcome of a multi-step run: the ordered tool names called, the model's
    final answer, how many turns it took, and an error string if the loop failed
    or hit max_steps."""
    trajectory: list[str]
    final_answer: str
    steps: int
    error: str | None = None
```

Refactor the retry/post logic out of `call` into a shared helper, then rewrite `call` to use it, and add `run_agent`. Replace the entire existing `async def call(...)` method with:

```python
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
        max_steps: int = 8,
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest evals/tests/test_agentic.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Verify `call` still works (no regression)**

Run: `uv run pytest evals/ -q`
Expected: all existing eval-harness tests still pass.

- [ ] **Step 6: Commit**

```bash
git add evals/run.py evals/tests/test_agentic.py
git commit -m "feat(evals): ModelClient.run_agent multi-step loop + AgentRun"
```

---

### Task 2: `evals/agentic.py` — prompt, mocks, scoring, run_scenario

**Files:**
- Create: `evals/agentic.py`
- Test: `evals/tests/test_agentic.py` (append)

**Interfaces:**
- Consumes: `AgentRun`, `ModelClient`, `combined_tool_schemas` from `run.py`.
- Produces:
  - `SKILLS_DIR: Path` (the repo's `skills/`).
  - `load_procedure(skill: str) -> str` — the `## Procedure` section text of `skills/<skill>/SKILL.md`.
  - `build_system_prompt(skill: str) -> str`
  - `make_mock_fn(scenario: dict) -> Callable[[str, dict], list]`
  - `score_run(scenario: dict, run: AgentRun) -> dict` → `{coverage, goal_reached, passed, trajectory, error}`
  - `load_scenario(path) -> dict`, `SCENARIOS_DIR: Path`
  - `async run_scenario(client: ModelClient, scenario: dict) -> dict`

- [ ] **Step 1: Write the failing test (append to `evals/tests/test_agentic.py`)**

```python
from evals.agentic import make_mock_fn, score_run


def _scenario() -> dict:
    return {
        "skill": "intune/coverage-gap-review",
        "task": "Which devices are stale or non-compliant?",
        "required_tools": ["get_compliance_summary", "list_stale_devices", "list_managed_devices"],
        "goal_keywords": ["stale", "unencrypt"],
        "mocks": {"get_compliance_summary": [{"x": 1}]},
    }


def test_make_mock_fn_returns_canned_then_graceful():
    fn = make_mock_fn(_scenario())
    assert fn("get_compliance_summary", {}) == [{"x": 1}]
    # a tool with no mock → graceful, non-crashing
    assert fn("list_stale_devices", {})[0]["note"].startswith("no mock")


def test_score_run_full_coverage_and_goal():
    run = AgentRun(
        trajectory=["get_compliance_summary", "list_stale_devices", "list_managed_devices"],
        final_answer="3 stale devices and several unencrypted ones.", steps=4, error=None)
    s = score_run(_scenario(), run)
    assert s["coverage"] == 1.0 and s["goal_reached"] and s["passed"]


def test_score_run_partial_coverage_fails():
    run = AgentRun(trajectory=["get_compliance_summary"],  # missing 2 required tools
                   final_answer="stale and unencrypt", steps=2, error=None)
    s = score_run(_scenario(), run)
    assert s["coverage"] == pytest.approx(1 / 3) and not s["passed"]


def test_score_run_goal_missed_fails():
    run = AgentRun(
        trajectory=["get_compliance_summary", "list_stale_devices", "list_managed_devices"],
        final_answer="everything looks fine",  # no goal keywords
        steps=4, error=None)
    s = score_run(_scenario(), run)
    assert s["coverage"] == 1.0 and not s["goal_reached"] and not s["passed"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest evals/tests/test_agentic.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'evals.agentic'`.

- [ ] **Step 3: Implement `evals/agentic.py`**

```python
"""Multi-step (agentic) skill eval: can a small local model DRIVE a whole SKILL.md
procedure? Skill-adherence — the skill's Procedure is injected live — scored on a
dual metric: tool-coverage% (order-tolerant) + goal-reached (keyword check).

Deterministic per-scenario mock tools; local-only (needs Ollama), never CI. The
harness logic here is covered by evals/tests/test_agentic.py (offline, fake model).
"""
from __future__ import annotations

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
    marker = "## Procedure"
    if marker not in text:
        return ""
    after = text.split(marker, 1)[1]
    # cut at the next top-level section heading
    end = after.find("\n## ")
    body = after if end == -1 else after[:end]
    return marker + body.rstrip() + "\n"


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
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest evals/tests/test_agentic.py -q`
Expected: PASS (all Task 1 + Task 2 tests).

- [ ] **Step 5: Commit**

```bash
git add evals/agentic.py evals/tests/test_agentic.py
git commit -m "feat(evals): agentic scenario loading, mocks, and dual-metric scoring"
```

---

### Task 3: The three scenario files + a scenario-validity test

**Files:**
- Create: `evals/scenarios/triage-incident-cross-platform.yaml`
- Create: `evals/scenarios/intune-coverage-gap-review.yaml`
- Create: `evals/scenarios/defender-triage-incident.yaml`
- Test: `evals/tests/test_agentic.py` (append)

**Interfaces:**
- Consumes: `SCENARIOS_DIR`, `SKILLS_DIR`, `load_scenario` from `agentic.py`.
- Produces: three valid scenario YAMLs.

- [ ] **Step 1: Write the failing test (append)**

```python
from evals.agentic import SCENARIOS_DIR, SKILLS_DIR, load_scenario

_SCENARIO_FILES = sorted(SCENARIOS_DIR.glob("*.yaml"))


def test_scenarios_exist():
    assert len(_SCENARIO_FILES) == 3


@pytest.mark.parametrize("path", _SCENARIO_FILES, ids=lambda p: p.stem)
def test_scenario_valid(path):
    s = load_scenario(path)
    for key in ("skill", "task", "required_tools", "goal_keywords", "mocks"):
        assert s.get(key), f"{path.name}: missing '{key}'"
    # the skill's SKILL.md exists and has a Procedure
    assert (SKILLS_DIR / s["skill"] / "SKILL.md").exists(), f"{path.name}: skill not found"
    # every required tool has a mock (so a full run is deterministic)
    for tool in s["required_tools"]:
        assert tool in s["mocks"], f"{path.name}: required tool '{tool}' has no mock"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest evals/tests/test_agentic.py -k scenario -q`
Expected: FAIL — `test_scenarios_exist` (0 != 3), no scenario files yet.

- [ ] **Step 3: Create the three scenario files**

`evals/scenarios/triage-incident-cross-platform.yaml`:

```yaml
# Cross-platform 4-server pivot: Defender incident -> Entra user risk -> LC host
# telemetry -> PA technique weakness. The marquee multi-step skill.
skill: cross-platform/triage-incident-cross-platform
task: "Triage our top active Defender incident and give me the full cross-platform picture."
required_tools: [list_incidents, list_risky_users, get_sensor, query_telemetry, get_weak_techniques]
goal_keywords: ["web-01", "T1110", "risky"]
mocks:
  list_incidents:
    - schema_version: "1.0"
      source: defender
      finding_type: incident
      severity: high
      title: "Multi-stage incident on host web-01 involving alice@corp.local"
      entity: { kind: host, id: web-01, name: web-01.corp.local }
      evidence:
        - { key: user, value: alice@corp.local }
        - { key: status, value: active }
      references: [ { type: mitre, id: T1110 } ]
  list_alerts:
    - schema_version: "1.0"
      source: defender
      finding_type: alert
      severity: high
      title: "Brute-force authentication against web-01"
      references: [ { type: mitre, id: T1110 } ]
  list_risky_users:
    - schema_version: "1.0"
      source: entra
      finding_type: risk
      severity: high
      title: "Risky user alice@corp.local (risk level: high)"
      entity: { kind: user, id: alice@corp.local, name: Alice }
      evidence: [ { key: risk_level, value: high } ]
  list_risk_detections:
    - schema_version: "1.0"
      source: entra
      finding_type: risk
      severity: high
      title: "Impossible travel sign-in for alice@corp.local"
  get_sensor:
    - schema_version: "1.0"
      source: limacharlie
      finding_type: posture
      severity: info
      title: "Sensor web-01 online (windows)"
      entity: { kind: host, id: web-01, name: web-01.corp.local }
  query_telemetry:
    - schema_version: "1.0"
      source: limacharlie
      finding_type: hunt_result
      severity: medium
      title: "web-01: repeated failed logons then a successful NTLM auth"
  get_weak_techniques:
    - schema_version: "1.0"
      source: projectachilles
      finding_type: risk
      severity: high
      title: "T1110 Brute Force — weak (12% blocked)"
      references: [ { type: mitre, id: T1110 } ]
```

`evals/scenarios/intune-coverage-gap-review.yaml`:

```yaml
# Single-platform multi-step: scope the fleet, find stale devices, list the
# non-compliant ones, flag unencrypted.
skill: intune/coverage-gap-review
task: "Where are our Intune device coverage gaps — stale, non-compliant, or unencrypted?"
required_tools: [get_compliance_summary, list_stale_devices, list_managed_devices]
goal_keywords: ["stale", "unencrypt"]
mocks:
  get_compliance_summary:
    - schema_version: "1.0"
      source: intune
      finding_type: posture
      severity: high
      title: "Intune device compliance: 983/1479 compliant, 306 non-compliant"
      evidence:
        - { key: total, value: "1479" }
        - { key: noncompliant, value: "306" }
        - { key: unknown, value: "187" }
  list_stale_devices:
    - schema_version: "1.0"
      source: intune
      finding_type: posture
      severity: medium
      title: "Stale device SBTV8893: last sync 2025-11-18T17:55:02Z"
      entity: { kind: device, id: SBTV8893, name: SBTV8893 }
  list_managed_devices:
    - schema_version: "1.0"
      source: intune
      finding_type: posture
      severity: high
      title: "Managed device LAP-204: noncompliant"
      entity: { kind: device, id: LAP-204, name: LAP-204 }
      evidence:
        - { key: compliance, value: noncompliant }
        - { key: encrypted, value: "False" }
```

`evals/scenarios/defender-triage-incident.yaml`:

```yaml
# Single-platform multi-step: pull the incident, then its correlated alerts,
# summarize what happened + technique.
skill: defender/triage-incident
task: "Triage our active high-severity Defender incidents."
required_tools: [list_incidents, list_alerts]
goal_keywords: ["pc-9", "T1059"]
mocks:
  list_incidents:
    - schema_version: "1.0"
      source: defender
      finding_type: incident
      severity: high
      title: "Suspicious PowerShell activity on host pc-9"
      entity: { kind: host, id: pc-9, name: pc-9.corp.local }
      references: [ { type: mitre, id: T1059 } ]
  list_alerts:
    - schema_version: "1.0"
      source: defender
      finding_type: alert
      severity: high
      title: "Encoded PowerShell command line on pc-9"
      entity: { kind: host, id: pc-9, name: pc-9.corp.local }
      references: [ { type: mitre, id: T1059 } ]
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest evals/tests/test_agentic.py -k scenario -q`
Expected: PASS (`test_scenarios_exist` + 3 parametrized `test_scenario_valid`).

- [ ] **Step 5: Commit**

```bash
git add evals/scenarios/
git commit -m "feat(evals): three agentic scenarios (cross-platform, intune, defender)"
```

---

### Task 4: `evals/agentic_scorecard.py` — skill×model matrix generator

**Files:**
- Create: `evals/agentic_scorecard.py`
- Test: `evals/tests/test_agentic.py` (append)

**Interfaces:**
- Consumes: `run_scenario`, `SCENARIOS_DIR`, `load_scenario` from `agentic.py`; `ModelClient` from `run.py`; `evals/models.yaml`.
- Produces:
  - `render_agentic_md(results: dict) -> str` — skill (rows) × model (cols) matrix, each cell `coverage% / goal-rate`.
  - `AGENTIC_MD: Path` (`evals/AGENTIC.md`), `_FINDINGS_MARKER`, `write_agentic_md(results, path=None)`.
  - `main()` — argparse runner (mirrors `scorecard.py`: `--base-url`, `--models`, `--runs`, `--date`, resumable JSON in `evals/results/agentic-<date>.json`).

- [ ] **Step 1: Write the failing test (append) — render is pure, test it offline**

```python
from evals.agentic_scorecard import render_agentic_md


def test_render_agentic_md_matrix():
    results = {
        "base_url": "http://localhost:11434/v1", "runs": 1, "date": "2026-07-12",
        "models": [{"tag": "granite4:tiny-h-c128k", "display": "Granite 4 Tiny"}],
        "skills": ["intune-coverage-gap-review"],
        "cells": {
            "granite4:tiny-h-c128k::intune-coverage-gap-review":
                {"coverage": 1.0, "goal_rate": 1.0, "runs": 1},
        },
    }
    md = render_agentic_md(results)
    assert "Granite 4 Tiny" in md
    assert "intune-coverage-gap-review" in md
    assert "100% / 100%" in md
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest evals/tests/test_agentic.py -k render -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'evals.agentic_scorecard'`.

- [ ] **Step 3: Implement `evals/agentic_scorecard.py`**

```python
"""Skill x model matrix for the agentic (multi-step) eval — sibling of scorecard.py.

Runs every scenario in evals/scenarios/ against every model in evals/models.yaml,
scoring coverage% + goal-rate, and renders evals/AGENTIC.md. Resumable, date-stamped
JSON in evals/results/. Local-only (needs Ollama); never run in CI. Evict models
between runs on a memory-constrained box (see evals/README.md), as with scorecard.py.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import yaml

from .agentic import SCENARIOS_DIR, load_scenario, run_scenario
from .run import ModelClient
from .scorecard import load_models  # reuse the models.yaml loader

EVALS = Path(__file__).resolve().parent
RESULTS_DIR = EVALS / "results"
AGENTIC_MD = EVALS / "AGENTIC.md"
_FINDINGS_MARKER = "<!-- findings below: hand-annotated, preserved when the table is regenerated -->"


def cell_key(tag: str, skill: str) -> str:
    return f"{tag}::{skill}"


def render_agentic_md(results: dict) -> str:
    cells = results.get("cells", {})
    cell_pairs = [k.split("::", 1) for k in cells if "::" in k]

    skills = list(results.get("skills", []))
    for _, skill in cell_pairs:
        if skill not in skills:
            skills.append(skill)

    models = list(results.get("models", []))
    known = {m["tag"] for m in models}
    for tag, _ in cell_pairs:
        if tag not in known:
            models.append({"tag": tag, "display": tag})
            known.add(tag)

    head = "| Skill | " + " | ".join(m["display"] for m in models) + " |"
    sep = "|" + "---|" * (len(models) + 1)
    lines = [
        "# Multi-step (agentic) skill scorecard",
        "",
        f"Endpoint `{results.get('base_url', '')}` · runs/scenario {results.get('runs', 1)} "
        f"· generated {results.get('date', '')}",
        "",
        "Each cell is **tool-coverage% / goal-reached%** for a model driving that skill's "
        "full procedure against deterministic mock tools. `err` = model/endpoint error; "
        "`–` = not run.",
        "",
        head,
        sep,
    ]
    for skill in skills:
        row = [skill]
        for m in models:
            cell = cells.get(cell_key(m["tag"], skill))
            if not cell:
                row.append("–")
            elif cell.get("error"):
                row.append("err")
            else:
                row.append(f"{cell['coverage']:.0%} / {cell['goal_rate']:.0%}")
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def write_agentic_md(results: dict, path: Path | None = None) -> None:
    path = path or AGENTIC_MD
    table = render_agentic_md(results)
    existing = path.read_text() if path.exists() else ""
    tail = (_FINDINGS_MARKER + existing.split(_FINDINGS_MARKER, 1)[1]) if _FINDINGS_MARKER in existing \
        else _FINDINGS_MARKER + "\n"
    path.write_text(table + "\n" + tail)


async def _amain(args: argparse.Namespace) -> None:
    models = load_models()
    if args.models:
        wanted = {t.strip() for t in args.models.split(",")}
        models = [m for m in models if m["tag"] in wanted]
    scenarios = [(p.stem, load_scenario(p)) for p in sorted(SCENARIOS_DIR.glob("*.yaml"))]

    RESULTS_DIR.mkdir(exist_ok=True)
    results_path = RESULTS_DIR / f"agentic-{args.date}.json"
    results = json.loads(results_path.read_text()) if results_path.exists() else {}
    results.update({"base_url": args.base_url, "runs": args.runs, "date": args.date,
                    "models": models, "skills": [name for name, _ in scenarios]})
    cells = results.setdefault("cells", {})

    for m in models:
        async with ModelClient(args.base_url, m["tag"]) as client:
            for name, scenario in scenarios:
                key = cell_key(m["tag"], name)
                if key in cells and not args.force:
                    continue
                cov_sum = goal_sum = 0.0
                err = None
                for _ in range(args.runs):
                    scored = await run_scenario(client, scenario)
                    cov_sum += scored["coverage"]
                    goal_sum += 1.0 if scored["goal_reached"] else 0.0
                    err = scored["error"] or err
                cells[key] = {"coverage": cov_sum / args.runs,
                              "goal_rate": goal_sum / args.runs,
                              "runs": args.runs, "error": err}
        results_path.write_text(json.dumps(results, indent=2, default=str))
        write_agentic_md(results)
        print(f"scored {m['tag']}")
    print(f"Wrote {AGENTIC_MD}")


def main() -> None:
    p = argparse.ArgumentParser(description="f0_sectools agentic skill scorecard (skill x model)")
    p.add_argument("--base-url", default="http://localhost:11434/v1")
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--models", default=None, help="comma-separated tags; default all in models.yaml")
    p.add_argument("--date", default="2026-07-12", help="date stamp for the results file")
    p.add_argument("--force", action="store_true", help="re-run cells already present")
    asyncio.run(_amain(p.parse_args()))


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest evals/tests/test_agentic.py -q`
Expected: PASS (all agentic tests).

- [ ] **Step 5: Lint**

Run: `uv run ruff check evals/`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add evals/agentic_scorecard.py evals/tests/test_agentic.py
git commit -m "feat(evals): agentic skill x model scorecard matrix generator"
```

---

### Task 5: Remove Ministral 3 from models.yaml + document the agentic eval

**Files:**
- Modify: `evals/models.yaml`
- Modify: `evals/README.md`

- [ ] **Step 1: Remove Ministral 3 from `evals/models.yaml`**

Delete this line from `evals/models.yaml`:

```yaml
- { tag: "ministral-3:ctx16k",    display: "Ministral 3 (8.9B)" }
```

- [ ] **Step 2: Verify models.yaml still loads and Ministral is gone**

Run: `uv run python -c "from evals.scorecard import load_models; ms=load_models(); print(len(ms), 'models'); assert not any('ministral' in m['tag'].lower() for m in ms), 'ministral still present'"`
Expected: prints `7 models` and no assertion error.

- [ ] **Step 3: Document the agentic eval in `evals/README.md`**

Append a section to `evals/README.md`:

```markdown
## Multi-step (agentic) skill eval

`evals/agentic.py` + `evals/agentic_scorecard.py` measure whether a model can drive a
whole `SKILL.md` **procedure**, not just pick one tool. Each scenario in
`evals/scenarios/*.yaml` injects the skill's live `## Procedure`, runs a multi-step
tool-calling loop against deterministic mock tool results, and scores a dual metric —
**tool-coverage%** (order-tolerant) and **goal-reached%** (keyword check on the final
answer). It is local-only (needs Ollama); the harness logic is covered offline by
`evals/tests/test_agentic.py`.

Run the matrix (evict between models on a memory-constrained box, as with the scorecard):

    for tag in $(python -c "import yaml;[print(m['tag']) for m in yaml.safe_load(open('evals/models.yaml'))]"); do
      uv run python -m evals.agentic_scorecard --models "$tag" --date 2026-07-12
      curl -s http://localhost:11434/api/chat -d "{\"model\":\"$tag\",\"messages\":[],\"keep_alive\":0}" >/dev/null
    done

Results render to `evals/AGENTIC.md` (a skill × model matrix). Ministral 3 was removed
from `models.yaml` — it emits no OpenAI `tool_calls`, so it scores 0 on both evals.
```

- [ ] **Step 4: Verify + lint**

Run: `uv run pytest evals/ -q && uv run ruff check evals/`
Expected: all pass, clean.

- [ ] **Step 5: Commit**

```bash
git add evals/models.yaml evals/README.md
git commit -m "chore(evals): drop Ministral 3 (no tool_calls); document the agentic eval"
```

---

## Self-Review

**1. Spec coverage:**
- `run_agent` multi-turn loop + `AgentRun` → Task 1. ✓
- Skill-adherence prompt (live Procedure) → Task 2 (`load_procedure`/`build_system_prompt`). ✓
- Deterministic name-keyed mocks + graceful no-mock → Task 2 (`make_mock_fn`) + Task 1 test. ✓
- Dual metric (coverage% + goal-reached), pass rule → Task 2 (`score_run`) + tests. ✓
- 3 scenarios (cross-platform + intune + defender) → Task 3. ✓
- Skill×model matrix + AGENTIC.md + resumable JSON → Task 4. ✓
- Offline harness contract test (fake model, partial-coverage, goal-missed, max_steps, no-mock) → Tasks 1–4 tests. ✓
- Ministral removed from models.yaml → Task 5. ✓
- README docs → Task 5. ✓
- Model sees combined 28-tool registry → Task 2 (`run_scenario` uses `combined_tool_schemas`). ✓
- Local-only / not CI (harness test IS offline) → every test uses the fake model or pure render. ✓

**2. Placeholder scan:** No TBD/TODO; every code + YAML block is complete verbatim; every doc edit shows exact strings.

**3. Type consistency:** `AgentRun` fields (`trajectory`/`final_answer`/`steps`/`error`), `run_agent`/`_post_chat`/`run_scenario`/`score_run`/`make_mock_fn` signatures, `cell_key`/`render_agentic_md` names, and the scenario keys (`skill`/`task`/`required_tools`/`goal_keywords`/`mocks`) are used identically across tasks and tests. `load_models` is imported from `scorecard.py` (exists). Scenario `skill` paths (`cross-platform/triage-incident-cross-platform`, `intune/coverage-gap-review`, `defender/triage-incident`) match real `skills/` dirs.
