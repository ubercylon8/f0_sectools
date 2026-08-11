"""Contract tests for Sentinel error mapping."""
from __future__ import annotations

from f0_sectools_core.auth.graph import GraphError
from f0_sentinel_mcp.errors import map_sentinel_error


def test_401_returns_posture_not_exception():
    f = map_sentinel_error(GraphError(401, "unauthorized"), "Sentinel firewall telemetry")
    assert f is not None
    assert f.finding_type.value == "posture"
    assert "Sentinel firewall telemetry" in f.title


def test_403_logs_half_names_log_analytics_reader():
    f = map_sentinel_error(GraphError(403, "forbidden"), "firewall telemetry", half="logs")
    assert f is not None
    assert "Log Analytics Reader" in (f.recommended_action.summary if f.recommended_action else "")


def test_403_arm_half_names_sentinel_reader():
    # The two halves fail independently; telling the operator to grant the wrong
    # role is worse than saying nothing.
    f = map_sentinel_error(GraphError(403, "forbidden"), "detection coverage", half="arm")
    assert f is not None
    assert "Microsoft Sentinel Reader" in (
        f.recommended_action.summary if f.recommended_action else ""
    )


def test_429_rate_limited():
    f = map_sentinel_error(GraphError(429, "throttled"), "Sentinel incidents")
    assert f is not None and "Rate limited" in f.title


def test_503_api_unavailable():
    f = map_sentinel_error(GraphError(503, "bad gateway"), "Sentinel incidents")
    assert f is not None and "unavailable" in f.title.lower()


def test_400_semantic_error_carries_reason_so_model_can_self_correct():
    f = map_sentinel_error(
        GraphError(400, "SemanticError: 'summarize' operator: Failed to resolve 'ObservableType'"),
        "Sentinel KQL query",
    )
    assert f is not None
    assert f.finding_type.value == "posture"
    assert "ObservableType" in f.title or "ObservableType" in (
        f.recommended_action.summary if f.recommended_action else ""
    )


def test_504_timeout_suggests_narrowing():
    f = map_sentinel_error(GraphError(504, "gateway timeout"), "Sentinel firewall telemetry")
    assert f is not None
    assert f.finding_type.value == "posture"


def test_non_graph_error_returns_none_so_caller_reraises():
    assert map_sentinel_error(ValueError("nope"), "x") is None
