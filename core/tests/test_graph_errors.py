from f0_sectools_core.auth.graph import GraphError
from f0_sectools_core.graph_errors import map_graph_error


def test_403_maps_to_permission_finding():
    e = GraphError(403, "forbidden")
    f = map_graph_error(e, "defender", "Machine.Isolate", "host isolation")
    assert f is not None
    assert "Machine.Isolate" in f.title


def test_429_maps_to_rate_limited_finding():
    e = GraphError(429, "throttled")
    f = map_graph_error(e, "defender", "Machine.Isolate", "host isolation")
    assert f is not None
    assert "Rate limited" in f.title


def test_503_maps_to_api_unavailable_finding():
    e = GraphError(503, "x")
    f = map_graph_error(e, "defender", "Machine.Isolate", "host isolation")
    assert f is not None
    assert "unavailable" in f.title


def test_unmapped_status_returns_none():
    e = GraphError(400, "bad request")
    f = map_graph_error(e, "defender", "Machine.Isolate", "host isolation")
    assert f is None
