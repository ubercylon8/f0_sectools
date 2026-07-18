"""Error-to-finding mapping tests, including the write-scope 403 hint."""
from __future__ import annotations

from f0_pa_actions_mcp.client import ProjectAchillesError
from f0_pa_actions_mcp.errors import map_pa_error
from f0_sectools_core.schema.findings import FindingType, Severity


def test_401_maps_to_auth_posture_finding():
    f = map_pa_error(ProjectAchillesError(401, "bad key"), "run test")
    assert f is not None
    assert f.finding_type == FindingType.posture
    assert "authentication failed" in f.title.lower()


def test_403_names_read_write_scope():
    f = map_pa_error(ProjectAchillesError(403, "Missing permission"), "run test")
    assert f is not None
    assert "read-write" in f.title or "read-write" in f.recommended_action.summary


def test_429_maps_to_rate_limited():
    f = map_pa_error(ProjectAchillesError(429, "slow down"), "run test")
    assert f is not None
    assert "rate limited" in f.title.lower()


def test_503_maps_to_unavailable():
    f = map_pa_error(ProjectAchillesError(503, "upstream"), "run test")
    assert f is not None
    assert "unavailable" in f.title.lower()


def test_400_maps_to_rejected_finding_with_message():
    f = map_pa_error(ProjectAchillesError(400, "task already terminal"), "cancel task")
    assert f is not None
    assert f.severity == Severity.info
    assert any("task already terminal" in ev.value for ev in f.evidence)


def test_404_maps_to_rejected_finding():
    f = map_pa_error(ProjectAchillesError(404, "Schedule not found"), "pause schedule")
    assert f is not None
    assert "404" in f.title


def test_unknown_status_returns_none():
    assert map_pa_error(ProjectAchillesError(418, "teapot"), "x") is None


def test_non_pa_error_returns_none():
    assert map_pa_error(ValueError("nope"), "x") is None
