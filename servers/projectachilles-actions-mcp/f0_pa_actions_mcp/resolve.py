"""Pre-gate resolution: turn the model's (test_id, hostname) into the full
backend payload facts. Any failure raises ResolveFailed carrying a graceful
finding — resolution ALWAYS runs before the gate, so a bad input never burns
an operator confirmation token or touches a write endpoint.
"""
from __future__ import annotations

import re
from typing import Any

from f0_sectools_core.schema.findings import (
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from .client import ProjectAchillesError
from .errors import map_pa_error

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ResolveFailed(Exception):
    """Resolution/validation failure carrying the finding to return."""

    def __init__(self, finding: Finding) -> None:
        self.finding = finding
        super().__init__(finding.title)


def guidance(title: str, summary: str) -> Finding:
    return Finding(
        source="projectachilles",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=title,
        recommended_action=RecommendedAction(summary=summary, confidence="high"),
    )


def _mapped(e: Exception, capability: str) -> ResolveFailed:
    finding = map_pa_error(e, capability)
    if finding:
        return ResolveFailed(finding)
    raise e


def _task_metadata(t: dict[str, Any]) -> dict[str, Any]:
    # Backend Zod TaskTestMetadataSchema: optional as a whole, but if present
    # EVERY key must be present (no per-field optionality). snake_case on the
    # wire; the browser test record is camelCase (threatActor).
    return {
        "category": str(t.get("category") or ""),
        "subcategory": str(t.get("subcategory") or ""),
        "severity": str(t.get("severity") or ""),
        "techniques": list(t.get("techniques") or []),
        "tactics": list(t.get("tactics") or []),
        "threat_actor": str(t.get("threatActor") or ""),
        "target": list(t.get("target") or []),
        "complexity": str(t.get("complexity") or ""),
        "tags": list(t.get("tags") or []),
        "score": t.get("score"),
        "integrations": list(t.get("integrations") or []),
    }


async def resolve_test(pa: Any, test_id: str) -> dict[str, Any]:
    """test_id (UUID) -> {test_uuid, test_name, metadata}."""
    tid = test_id.strip()
    if not _UUID_RE.match(tid):
        raise ResolveFailed(
            guidance(
                f"test_id must be a test UUID, got '{tid or '(empty)'}'",
                "Look the test up first with find_tests/get_test on the "
                "ProjectAchilles read server, then pass its uuid.",
            )
        )
    try:
        resp = await pa.get(f"/browser/tests/{tid}")
    except ProjectAchillesError as e:
        if e.status == 404:
            raise ResolveFailed(
                guidance(
                    f"Test {tid} not found in the ProjectAchilles catalog",
                    "Verify the uuid with find_tests on the read server.",
                )
            ) from e
        raise _mapped(e, "test lookup") from e
    t = resp.get("test") if isinstance(resp, dict) else None
    if not isinstance(t, dict):
        raise ResolveFailed(
            guidance(
                f"Test {tid} not found in the ProjectAchilles catalog",
                "Verify the uuid with find_tests on the read server.",
            )
        )
    return {
        "test_uuid": str(t.get("uuid") or tid),
        "test_name": str(t.get("name") or ""),
        "metadata": _task_metadata(t),
    }


async def resolve_build(pa: Any, test_uuid: str) -> str:
    """test_uuid -> built binary filename. Not-built is HTTP 200 + exists:false."""
    try:
        resp = await pa.get(f"/tests/builds/{test_uuid}")
    except ProjectAchillesError as e:
        raise _mapped(e, "build lookup") from e
    d = resp.get("data") if isinstance(resp, dict) else None
    d = d if isinstance(d, dict) else {}
    if not d.get("exists") or not d.get("filename"):
        raise ResolveFailed(
            guidance(
                f"Test {test_uuid} is not built — cannot run or schedule it",
                "Build & sign the test in the ProjectAchilles console "
                "(Tests -> Build) first, then retry.",
            )
        )
    return str(d["filename"])


async def resolve_agent(pa: Any, hostname: str) -> dict[str, str]:
    """hostname (exact, case-insensitive) -> {agent_id, org_id, hostname}."""
    h = hostname.strip()
    if not h:
        raise ResolveFailed(
            guidance(
                "hostname is required",
                "Pass the exact agent hostname; list agents with list_agents "
                "on the read server.",
            )
        )
    try:
        resp = await pa.get("/agent/admin/agents", params={"limit": 200})
    except ProjectAchillesError as e:
        raise _mapped(e, "agent lookup") from e
    data = resp.get("data") if isinstance(resp, dict) else None
    agents = (data.get("agents") if isinstance(data, dict) else data) or []
    matches = [
        a for a in agents
        if isinstance(a, dict) and str(a.get("hostname", "")).lower() == h.lower()
    ]
    if not matches:
        raise ResolveFailed(
            guidance(
                f"No ProjectAchilles agent with hostname '{h}'",
                "Check the hostname with list_agents on the read server "
                "(exact match required).",
            )
        )
    if len(matches) > 1:
        raise ResolveFailed(
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Multiple agents match hostname '{h}' — ambiguous target",
                evidence=[
                    Evidence(key=str(a.get("hostname", "?")), value=str(a.get("id", "")))
                    for a in matches[:10]
                ],
                recommended_action=RecommendedAction(
                    summary="Disambiguate in the PA console; v1 targets exactly "
                    "one agent per call.",
                    confidence="high",
                ),
            )
        )
    a = matches[0]
    agent_id = str(a.get("id") or "")
    org_id = str(a.get("org_id") or "")
    if not org_id and agent_id:
        # The admin LIST endpoint strips org_id (verified live 2026-07-18); the
        # single-agent DETAIL endpoint keeps it. Without it the create payload
        # fails the backend's "org_id is required" check.
        try:
            detail = await pa.get(f"/agent/admin/agents/{agent_id}")
        except ProjectAchillesError as e:
            raise _mapped(e, "agent org lookup") from e
        d2 = detail.get("data") if isinstance(detail, dict) else None
        if isinstance(d2, dict):
            org_id = str(d2.get("org_id") or "")
    return {
        "agent_id": agent_id,
        "org_id": org_id,
        "hostname": str(a.get("hostname") or h),
    }
