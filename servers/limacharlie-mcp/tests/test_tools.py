"""Contract tests for the LimaCharlie tools.

The tools take a thin client wrapper; tests pass a fake client (no SDK / network).
Real dict key names are validated by the live smoke test.
"""
from __future__ import annotations

from f0_limacharlie_mcp import tools
from limacharlie.errors import PermissionDeniedError, RateLimitError


class FakeClient:
    """Fake LimaCharlieClient: canned data, or raises a configured error."""

    def __init__(self, **overrides):
        self._raise = overrides.pop("raise_on", {})
        self._data = overrides

    def _maybe_raise(self, name):
        if name in self._raise:
            raise self._raise[name]

    def org_info(self):
        self._maybe_raise("org_info")
        return self._data.get("org_info", {"oid": "org-1", "name": "Acme"})

    def org_stats(self):
        return self._data.get("org_stats", {})

    def list_sensors(self, online_only=False, limit=50):
        self._maybe_raise("list_sensors")
        return self._data.get("sensors", [])

    def find_sensor(self, hostname):
        self._maybe_raise("find_sensor")
        return self._data.get("find_sensor", {})

    def list_dr_rules(self, namespace="general"):
        self._maybe_raise("list_dr_rules")
        return self._data.get("dr_rules", {})

    def list_detections(self, start, end, limit=50, category=None):
        self._maybe_raise("list_detections")
        return self._data.get("detections", [])

    def query(self, lcql, start, end, limit=50):
        self._maybe_raise("query")
        return self._data.get("query", [])


def test_list_sensors_maps():
    lc = FakeClient(sensors=[
        {"sid": "s1", "hostname": "web-01", "platform": "windows", "is_online": True},
    ])
    findings = tools.list_sensors(lc)
    assert findings[0].entity.name == "web-01"
    assert findings[0].finding_type.value == "posture"


def test_list_detections_maps():
    lc = FakeClient(detections=[
        {"cat": "Suspicious PowerShell", "routing": {"hostname": "web-01"}, "detect_id": "d1"},
    ])
    findings = tools.list_detections(lc)
    assert findings[0].finding_type.value == "alert"
    assert "Suspicious PowerShell" in findings[0].title


def test_list_dr_rules_maps():
    lc = FakeClient(dr_rules={"win-creds-dump": {"detect": {}, "respond": []}})
    findings = tools.list_dr_rules(lc)
    assert any("win-creds-dump" in f.title for f in findings)


def test_query_telemetry_maps():
    lc = FakeClient(query=[{"event": {"FILE_PATH": "x"}}, {"event": {"FILE_PATH": "y"}}])
    findings = tools.query_telemetry(lc, "plat == windows | NEW_PROCESS | * | *")
    assert findings[0].finding_type.value == "hunt_result"
    assert "2" in findings[0].title


def test_get_org_overview_maps():
    lc = FakeClient(
        org_info={"oid": "org-1", "name": "Acme"},
        sensors=[{"sid": "s1", "is_online": True}, {"sid": "s2", "is_online": False}],
        dr_rules={"r1": {}, "r2": {}},
        detections=[{"cat": "x"}],
    )
    findings = tools.get_org_overview(lc)
    assert findings[0].finding_type.value == "posture"
    assert "2" in findings[0].title or any("2" in e.value for e in findings[0].evidence)


def test_list_sensors_permission_denied_degrades():
    lc = FakeClient(raise_on={"list_sensors": PermissionDeniedError("denied")})
    findings = tools.list_sensors(lc)
    assert findings[0].finding_type.value == "posture"
    assert "not granted" in findings[0].title.lower() or "permission" in findings[0].title.lower()


def test_list_detections_rate_limited_degrades():
    lc = FakeClient(raise_on={"list_detections": RateLimitError("slow down")})
    findings = tools.list_detections(lc)
    assert findings[0].finding_type.value == "posture"
    assert "rate limited" in findings[0].title.lower()
