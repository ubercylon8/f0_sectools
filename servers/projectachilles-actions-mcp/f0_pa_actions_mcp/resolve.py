"""Pre-gate resolution: turn the model's (test_id, hostname) into the full
backend payload facts. Any failure raises ResolveFailed carrying a graceful
finding — resolution ALWAYS runs before the gate, so a bad input never burns
an operator confirmation token or touches a write endpoint.
"""
from __future__ import annotations

import re
from typing import Any, cast

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
_TAG_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,64}$")
_MAX_FLEET = 200


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


async def resolve_agents_by_tag(pa: Any, tag: str) -> dict[str, Any]:
    """tag -> {agent_ids, hostnames, org_id} for every agent carrying it.

    Refuses (>_MAX_FLEET) rather than silently run on a capped subset — a
    hidden blast-radius cap is unacceptable for an attack-simulation launcher.
    """
    t = tag.strip()
    if not t or not _TAG_RE.match(t):
        raise ResolveFailed(
            guidance(
                f"tag '{t or '(empty)'}' is missing or has unsupported characters",
                "Use a tag as shown in the ProjectAchilles console "
                "(letters, digits, . _ : @ -).",
            )
        )
    try:
        resp = await pa.get("/agent/admin/agents", params={"tag": t, "limit": _MAX_FLEET})
    except ProjectAchillesError as e:
        raise _mapped(e, "agent tag lookup") from e
    data = resp.get("data") if isinstance(resp, dict) else None
    data = data if isinstance(data, dict) else {}
    agents_raw = data.get("agents")
    agents = agents_raw if isinstance(agents_raw, list) else []
    total = data.get("total")
    if (isinstance(total, int) and not isinstance(total, bool) and total > _MAX_FLEET) or (
        total is None and len(agents) >= _MAX_FLEET
    ):
        raise ResolveFailed(
            guidance(
                f"Tag '{t}' matches more than {_MAX_FLEET} agents — refusing to fan out",
                f"Narrow the tag so it selects at most {_MAX_FLEET} hosts, then retry.",
            )
        )
    if not agents:
        raise ResolveFailed(
            guidance(
                f"No agents carry tag '{t}'",
                "Check the tag in the ProjectAchilles console (agent tags).",
            )
        )
    # Build both lists from the SAME filtered set of valid records (dicts with truthy id)
    # to keep agent_ids and hostnames index-aligned. A record with no id is dropped from both.
    valid = [a for a in agents if isinstance(a, dict) and a.get("id")]
    agent_ids = [str(a["id"]) for a in valid]
    hostnames = [str(a.get("hostname") or "?") for a in valid]
    # org_id once from the first agent's detail (the admin list strips it).
    org_id = ""
    if agent_ids:
        try:
            detail = await pa.get(f"/agent/admin/agents/{agent_ids[0]}")
        except ProjectAchillesError as e:
            raise _mapped(e, "agent org lookup") from e
        d2 = detail.get("data") if isinstance(detail, dict) else None
        if isinstance(d2, dict):
            org_id = str(d2.get("org_id") or "")
    return {"agent_ids": agent_ids, "hostnames": hostnames, "org_id": org_id}


async def resolve_selection(pa: Any, hostname: str, tag: str) -> dict[str, Any]:
    """Normalize host-or-tag targeting. Exactly one of hostname/tag must be set."""
    h, t = hostname.strip(), tag.strip()
    if bool(h) == bool(t):
        raise ResolveFailed(
            guidance(
                "Set exactly one of hostname or tag",
                "hostname targets ONE host; tag targets every agent carrying "
                "that tag (a fleet).",
            )
        )
    if h:
        a = await resolve_agent(pa, h)
        return {
            "agent_ids": [a["agent_id"]],
            "hostnames": [a["hostname"]],
            "org_id": a["org_id"],
            "target_key": a["hostname"],
            "label": a["hostname"],
            "count": 1,
            "is_fleet": False,
        }
    fleet = await resolve_agents_by_tag(pa, t)
    n = len(cast(list[str], fleet["agent_ids"]))
    # target_key includes the count N baked in; consumers must compare the WHOLE string
    # (never split on ':' — tags may legitimately contain ':', e.g. env:prod). The gate
    # catches blast-radius drift by comparing full target_key strings.
    return {
        "agent_ids": fleet["agent_ids"],
        "hostnames": fleet["hostnames"],
        "org_id": fleet["org_id"],
        "target_key": f"tag:{t}:{n}",
        "label": f"tag '{t}' ({n} host{'s' if n != 1 else ''})",
        "count": n,
        "is_fleet": True,
    }
