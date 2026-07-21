"""Contract tests for the LimaCharlie tools.

The tools take a thin client wrapper; tests pass a fake client (no SDK / network).
Real dict key names are validated by the live smoke test.
"""
from __future__ import annotations

import pytest
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

    def list_sensors(self, online_only=False, limit=50, tag=None):
        self._maybe_raise("list_sensors")
        self.last_sensors_tag = tag
        return self._data.get("sensors", [])

    def find_sensor(self, hostname):
        self._maybe_raise("find_sensor")
        return self._data.get("find_sensor", [])

    def get_sensor_tags(self, sid):
        self._maybe_raise("get_sensor_tags")
        self.tags_calls = getattr(self, "tags_calls", []) + [sid]
        return self._data.get("tags", {}).get(sid, [])

    def count_sensors_with_tag(self, tag):
        self._maybe_raise("count_sensors_with_tag")
        return self._data.get("tag_count", 0)

    def list_dr_rules(self, namespace="general"):
        self._maybe_raise("list_dr_rules")
        return self._data.get("dr_rules", {})

    def list_detections(self, start, end, limit=50, category=None):
        self._maybe_raise("list_detections")
        self.last_detections_limit = limit
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


def test_list_sensors_enforces_limit():
    lc = FakeClient(sensors=[{"sid": str(i), "hostname": f"h{i}"} for i in range(10)])
    assert len(tools.list_sensors(lc, limit=3)) == 3


def test_list_sensors_maps_platform_int():
    lc = FakeClient(sensors=[{"sid": "s1", "hostname": "win-01", "platform": 0x10000000}])
    plat = {e.key: e.value for e in tools.list_sensors(lc)[0].evidence}["platform"]
    assert plat == "windows"


def test_list_sensors_tag_filter_passes_through():
    # "which hosts carry tag X" — the platform filters server-side via the
    # sensor-selector ('"<tag>" in tags', probed live 2026-07-21).
    lc = FakeClient(sensors=[{"sid": "s1", "hostname": "web-01", "is_online": True}])
    findings = tools.list_sensors(lc, tag="prueba")
    assert lc.last_sensors_tag == "prueba"
    assert findings[0].entity.name == "web-01"


def test_list_sensors_empty_tag_means_unfiltered():
    # Small models emit "" for optional args — treat as unset, not invalid.
    lc = FakeClient(sensors=[{"sid": "s1", "hostname": "web-01"}])
    tools.list_sensors(lc, tag="")
    assert lc.last_sensors_tag is None


def test_list_sensors_rejects_unsafe_tag():
    # The tag is spliced into a double-quoted selector literal — same breakout
    # guard as hostname/domain. Client must never be called with an unsafe value.
    class _NeverList(FakeClient):
        def list_sensors(self, online_only=False, limit=50, tag=None):
            raise AssertionError("list_sensors must not run with an unsafe tag")

    findings = tools.list_sensors(_NeverList(), tag='x" | evil')
    assert findings[0].finding_type.value == "posture"
    assert "tag" in findings[0].title.lower()


def test_list_sensors_tag_with_no_matches_says_so():
    # An empty list is invisible to a small model; say explicitly no sensor
    # carries the tag (mirrors get_sensor's not-found finding).
    lc = FakeClient(sensors=[])
    findings = tools.list_sensors(lc, tag="ghost-tag")
    assert findings[0].finding_type.value == "posture"
    assert "ghost-tag" in findings[0].title


def test_list_detections_maps():
    lc = FakeClient(detections=[
        {"cat": "Suspicious PowerShell", "routing": {"hostname": "web-01"}, "detect_id": "d1"},
    ])
    findings = tools.list_detections(lc)
    assert findings[0].finding_type.value == "alert"
    assert "Suspicious PowerShell" in findings[0].title


def test_list_detections_clamps_oversized_limit():
    lc = FakeClient(detections=[])
    tools.list_detections(lc, limit=5000)
    assert lc.last_detections_limit == 100  # clamped from 5000


def test_list_dr_rules_maps():
    lc = FakeClient(dr_rules={"win-creds-dump": {"detect": {}, "respond": []}})
    findings = tools.list_dr_rules(lc)
    assert any("win-creds-dump" in f.title for f in findings)


def test_get_sensor_renders_full_record():
    # find_sensor now returns full sensor dicts (via list_sensors with_hostname_prefix),
    # not the minimal {"sid": [[sid, hostname]]} shape of find_sensors_by_hostname.
    lc = FakeClient(find_sensor=[
        {"sid": "07531c60", "hostname": "web-01.corp.local",
         "plat": 0x10000000, "is_online": True},
    ])
    findings = tools.get_sensor(lc, "web-01")
    assert findings[0].entity.name == "web-01.corp.local"
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["online"] == "True" and ev["platform"] == "windows"
    assert "online" in findings[0].title


def test_get_sensor_not_found():
    lc = FakeClient(find_sensor=[])
    findings = tools.get_sensor(lc, "nope")
    assert "No sensor found" in findings[0].title


def test_get_sensor_surfaces_tags_and_sleeper_state():
    # Tags live behind a separate endpoint; without them a dormant (lc:sleeper)
    # host is indistinguishable from a quiet one.
    lc = FakeClient(
        find_sensor=[{"sid": "s1", "hostname": "app-srv-01.corp.local",
                      "plat": 0x10000000, "is_online": True}],
        tags={"s1": ["lc:sleeper", "prueba"]},
    )
    findings = tools.get_sensor(lc, "app-srv-01")
    ev = {e.key: e.value for e in findings[0].evidence}
    assert "lc:sleeper" in ev["tags"] and "prueba" in ev["tags"]
    assert "dormant" in findings[0].title.lower()


def test_get_sensor_tags_failure_degrades_gracefully():
    lc = FakeClient(
        find_sensor=[{"sid": "s1", "hostname": "web-01", "is_online": True}],
        raise_on={"get_sensor_tags": RateLimitError("slow down")},
    )
    findings = tools.get_sensor(lc, "web-01")
    assert findings[0].entity.name == "web-01"  # record still rendered, tags just absent


# Live shape: lc.query returns result ENVELOPES; the events are nested under `.rows`.
_ENVELOPE = [{
    "searchResultId": "1", "type": "events",
    "rows": [
        {"mtd": {"id": "a"}, "data": {"event/FILE_PATH": "C:\\a.exe",
                                      "event/COMMAND_LINE": "a.exe -x"}},
        {"mtd": {"id": "b"}, "data": {"event/FILE_PATH": "C:\\b.exe",
                                      "event/COMMAND_LINE": "b.exe"}},
    ],
}]


def test_query_telemetry_flattens_envelope_into_per_event_findings():
    lc = FakeClient(query=_ENVELOPE)
    findings = tools.query_telemetry(lc, hunt="new_processes")
    # a leading summary + one finding PER EVENT (not one 700KB str(envelope) blob)
    assert findings[0].finding_type.value == "hunt_result"
    assert "2" in findings[0].title
    assert len(findings) == 1 + 2
    ev = {e.key: e.value for e in findings[1].evidence}
    assert ev["file_path"] == "C:\\a.exe"
    assert "a.exe" in ev["command_line"]


def test_query_telemetry_bounds_events_but_counts_all():
    rows = [{"mtd": {}, "data": {"event/FILE_PATH": f"f{i}"}} for i in range(60)]
    lc = FakeClient(query=[{"rows": rows}])
    findings = tools.query_telemetry(lc, hunt="new_processes", limit=5)
    ev0 = {e.key: e.value for e in findings[0].evidence}
    assert ev0["events_total"] == "60"
    assert len(findings) == 1 + 5  # summary + 5 events (bounded), count stays exact


def test_query_telemetry_scopes_preset_to_hostname():
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    lc = _Cap(find_sensor=[
        {"sid": "s1", "hostname": "web-01.corp.local", "is_online": True},
    ])
    tools.query_telemetry(lc, hunt="new_processes", hostname="web-01.corp.local")
    assert 'hostname == "web-01.corp.local"' in captured["lcql"]
    assert "NEW_PROCESS" in captured["lcql"]
    assert " * " in f" {captured['lcql']} " or "|" in captured["lcql"]  # still valid LCQL shape


def test_query_telemetry_resolves_short_hostname_to_full():
    # Sensors register FQDNs (web-02.corp.local); operators & models say
    # "web-02". Exact-matching the short name selected ZERO sensors and returned
    # 0 events on a host with ~1000 real events (live repro 2026-07-21). The tool
    # must resolve the short name to the stored hostname before scoping.
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": [{"data": {"event/FILE_PATH": "C:\\a.exe"}}]}]

    lc = _Cap(find_sensor=[
        {"sid": "s1", "hostname": "web-02.corp.local", "is_online": True},
    ])
    findings = tools.query_telemetry(lc, hunt="new_processes", hostname="web-02")
    assert 'hostname == "web-02.corp.local"' in captured["lcql"]
    # Scope label and entity carry the RESOLVED name, so the answer names the real host.
    assert "web-02.corp.local" in findings[0].title
    assert findings[0].entity.name == "web-02.corp.local"


def test_query_telemetry_unmatched_hostname_says_so():
    # No sensor matches -> an explicit finding, never a silent "0 events".
    lc = FakeClient(find_sensor=[])
    findings = tools.query_telemetry(lc, hunt="new_processes", hostname="ghost-99")
    assert findings[0].finding_type.value == "posture"
    assert "no sensor" in findings[0].title.lower()
    assert "ghost-99" in findings[0].title


def test_query_telemetry_ambiguous_hostname_lists_candidates():
    # A partial prefix matching several distinct hosts must ask for disambiguation,
    # not silently pick one (or query none).
    lc = FakeClient(find_sensor=[
        {"sid": "s1", "hostname": "app-srv-01.corp.local"},
        {"sid": "s2", "hostname": "app-srv-02.corp.local"},
    ])
    findings = tools.query_telemetry(lc, hunt="new_processes", hostname="app-srv-0")
    assert findings[0].finding_type.value == "posture"
    title_and_evidence = findings[0].title + " ".join(e.value for e in findings[0].evidence)
    assert "app-srv-01.corp.local" in title_and_evidence
    assert "app-srv-02.corp.local" in title_and_evidence


def test_query_telemetry_multi_sid_same_hostname_is_not_ambiguous():
    # Re-enrolled agents leave several sensor records with the SAME hostname —
    # hostname-scoping covers them all; that's a resolution, not an ambiguity.
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    lc = _Cap(find_sensor=[
        {"sid": "s1", "hostname": "web-01.corp.local", "is_online": False},
        {"sid": "s2", "hostname": "web-01.corp.local", "is_online": True},
    ])
    tools.query_telemetry(lc, hunt="new_processes", hostname="web-01")
    assert 'hostname == "web-01.corp.local"' in captured["lcql"]


def test_query_telemetry_zero_events_on_sleeper_host_says_dormant():
    # 1,173 of 1,247 sensors in the live org are lc:sleeper-tagged (dormant by
    # design). A zero-result on such a host must SAY so — the agent otherwise
    # invents wrong explanations ("recently rebooted").
    lc = FakeClient(
        find_sensor=[{"sid": "s1", "hostname": "app-srv-01.corp.local", "is_online": True}],
        tags={"s1": ["lc:sleeper"]},
        query=[{"rows": []}],
    )
    findings = tools.query_telemetry(lc, hunt="new_processes", hostname="app-srv-01")
    assert "dormant" in findings[0].title.lower()
    ev = {e.key: e.value for e in findings[0].evidence}
    assert "lc:sleeper" in ev["tags"]
    assert "sleeper" in findings[0].recommended_action.summary.lower()


def test_query_telemetry_zero_events_active_host_notes_online_state():
    lc = FakeClient(
        find_sensor=[{"sid": "s1", "hostname": "web-01.corp.local", "is_online": True}],
        tags={"s1": ["prueba"]},
        query=[{"rows": []}],
    )
    findings = tools.query_telemetry(lc, hunt="new_processes", hostname="web-01")
    assert "dormant" not in findings[0].title.lower()
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["sensor_online"] == "True"


def test_query_telemetry_skips_tags_lookup_when_events_found():
    # The tags call is diagnosis for a zero-result; don't spend an API call when
    # events came back.
    lc = FakeClient(
        find_sensor=[{"sid": "s1", "hostname": "web-01.corp.local", "is_online": True}],
        query=[{"rows": [{"data": {"event/FILE_PATH": "C:\\a.exe"}}]}],
    )
    tools.query_telemetry(lc, hunt="new_processes", hostname="web-01")
    assert getattr(lc, "tags_calls", []) == []


def test_query_telemetry_tags_lookup_failure_keeps_finding():
    # A tags-endpoint failure must not break the zero-result finding (Rule: every
    # failure becomes a finding, never an exception).
    lc = FakeClient(
        find_sensor=[{"sid": "s1", "hostname": "web-01.corp.local", "is_online": True}],
        raise_on={"get_sensor_tags": PermissionDeniedError("denied")},
        query=[{"rows": []}],
    )
    findings = tools.query_telemetry(lc, hunt="new_processes", hostname="web-01")
    assert findings[0].finding_type.value == "hunt_result"
    assert "0 telemetry event(s)" in findings[0].title


def test_query_telemetry_user_activity_preset():
    # 5th hunt preset: "what users were seen on host X" -> USER_OBSERVED, with
    # routing/hostname projected so fleet-wide runs say WHERE (probed live).
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    tools.query_telemetry(_Cap(), hunt="user_activity")
    assert "USER_OBSERVED" in captured["lcql"]
    assert "event/USER_NAME" in captured["lcql"]
    assert "routing/hostname" in captured["lcql"]


def test_query_telemetry_username_filters_boundary_anchored():
    # Windows reports "DOMAIN\\user"; a bare username must match the exact name
    # or a domain-qualified form at the backslash BOUNDARY — "xjsmith" must not.
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    findings = tools.query_telemetry(_Cap(), hunt="new_processes", username="jsmith")
    q = captured["lcql"]
    assert 'event/USER_NAME is "jsmith"' in q
    assert 'event/USER_NAME ends with "\\jsmith"' in q
    assert "by user jsmith" in findings[0].title


def test_query_telemetry_qualified_username_matches_exactly():
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    tools.query_telemetry(_Cap(), hunt="new_processes", username="CORP\\jsmith")
    q = captured["lcql"]
    assert 'event/USER_NAME is "CORP\\jsmith"' in q
    assert "ends with" not in q  # already domain-qualified: exact match only


def test_query_telemetry_username_composes_with_preset_filter():
    # powershell_activity already has a filter; the username clause must AND with
    # it, parenthesised so the OR stays grouped.
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    tools.query_telemetry(_Cap(), hunt="powershell_activity", username="jsmith")
    q = captured["lcql"]
    assert 'event/FILE_PATH contains "powershell"' in q
    assert 'and (event/USER_NAME is "jsmith"' in q


def test_query_telemetry_rejects_unsafe_username():
    class _NeverQuery(FakeClient):
        def query(self, lcql, start, end, limit=50):
            raise AssertionError("query must not run with an unsafe username")

    # A quote breaks out of the literal directly; a leading/trailing/double
    # backslash can escape the closing quote ('is "CORP\"' — CC review,
    # PR #59). Only ONE interior backslash (DOMAIN\user) is a valid shape.
    for bad in ('x" | evil', "CORP\\", "\\jsmith", "a\\b\\c"):
        findings = tools.query_telemetry(
            _NeverQuery(), hunt="new_processes", username=bad
        )
        assert findings[0].finding_type.value == "posture", bad
        assert "username" in findings[0].title.lower()


def test_query_telemetry_empty_username_is_unset():
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    findings = tools.query_telemetry(_Cap(), hunt="new_processes", username="")
    assert "USER_NAME is" not in captured["lcql"]
    assert "by user" not in findings[0].title


def test_query_telemetry_domain_wins_over_username():
    # DNS events carry no acting user; when both are given the domain routing
    # applies and the result must NOT be labelled by user.
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    findings = tools.query_telemetry(_Cap(), domain="microsoft.com", username="jsmith")
    assert "DNS_REQUEST" in captured["lcql"]
    assert "USER_NAME" not in captured["lcql"]
    assert "by user" not in findings[0].title


def test_query_telemetry_lcql_override_ignores_username():
    lc = FakeClient(query=[{"rows": []}])
    findings = tools.query_telemetry(
        lc, username="jsmith", lcql="-1h | * | DNS_REQUEST | * | event/DOMAIN_NAME"
    )
    assert "by user" not in findings[0].title


def test_query_telemetry_rejects_unsafe_stored_hostname():
    # The RESOLVED hostname comes from live platform data (agent-side enrollment),
    # not the validated caller argument — it must pass the same LCQL-safety check
    # before being spliced into the selector string, else a stored hostname with a
    # quote breaks out of the string literal (CC review, PR #58).
    class _NeverQuery(FakeClient):
        def query(self, lcql, start, end, limit=50):
            raise AssertionError("query must not run with an unsafe stored hostname")

    lc = _NeverQuery(find_sensor=[
        {"sid": "s1", "hostname": 'web-01.evil" | x', "is_online": True},
    ])
    findings = tools.query_telemetry(lc, hunt="new_processes", hostname="web-01")
    assert findings[0].finding_type.value == "posture"
    assert "hostname" in findings[0].title.lower()


def test_query_telemetry_resolution_ignores_deleted_sensors():
    lc = FakeClient(find_sensor=[
        {"sid": "s1", "hostname": "web-01.corp.local", "is_del": True},
    ])
    findings = tools.query_telemetry(lc, hunt="new_processes", hostname="web-01")
    assert "no sensor" in findings[0].title.lower()


def test_query_telemetry_rejects_injection_in_hostname():
    lc = FakeClient(query=[{"rows": []}])
    findings = tools.query_telemetry(lc, hunt="new_processes", hostname='x" | delete')
    assert findings[0].finding_type.value == "posture"
    assert "hostname" in findings[0].title.lower()


def test_query_telemetry_empty_hostname_runs_unscoped():
    # A small model may emit hostname="" for the optional arg — treat it as unscoped,
    # NOT as an invalid hostname.
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": [{"data": {"event/FILE_PATH": "x"}}]}]

    findings = tools.query_telemetry(_Cap(), hunt="new_processes", hostname="")
    assert "| * |" in captured["lcql"]  # unscoped selector, not rejected
    assert findings[0].finding_type.value == "hunt_result"
    assert findings[0].entity is None  # no host scope labelled


def test_query_telemetry_supports_sub_hour_window():
    # A small model naturally expresses "last 15 minutes" as hours_back=0.25.
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            captured["start"] = start
            return [{"rows": []}]

    tools.query_telemetry(_Cap(), hunt="dns_requests", hours_back=0.25)
    assert captured["lcql"].startswith("-15m ")  # minutes, not a rejected fractional hour
    assert isinstance(captured["start"], int)


def test_query_telemetry_whole_hours_use_hour_descriptor():
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    tools.query_telemetry(_Cap(), hunt="dns_requests", hours_back=24)
    assert captured["lcql"].startswith("-24h ")


def test_query_telemetry_renders_nested_event_data():
    # NETWORK_CONNECTIONS projects event/NETWORK_ACTIVITY as a nested list — it must
    # surface, not be dropped as a non-scalar (which produced empty findings).
    net = [{"DESTINATION": {"IP_ADDRESS": "18.190.167.133", "PORT": 443},
            "PROTOCOL": "tcp4", "IS_OUTGOING": 1}]
    lc = FakeClient(query=[{"rows": [{"data": {"event/NETWORK_ACTIVITY": net}}]}])
    findings = tools.query_telemetry(lc, hunt="network_connections")
    ev = {e.key: e.value for e in findings[1].evidence}
    assert "network_activity" in ev
    assert "18.190.167.133" in ev["network_activity"]  # nested content surfaced
    assert findings[1].title != "telemetry event"


def test_query_telemetry_redacts_secrets_in_nested_projection():
    # A nested projection value carrying a secret-named key must be key-hint redacted
    # BEFORE it's flattened to a string — else stringification defeats redact_obj's
    # key-hint pass and a low-entropy secret would leak (Critical Rule 3).
    nested = [{"password": "hunter2", "DESTINATION": {"IP_ADDRESS": "1.2.3.4"}}]
    lc = FakeClient(query=[{"rows": [{"data": {"event/NETWORK_ACTIVITY": nested}}]}])
    findings = tools.query_telemetry(lc, hunt="network_connections")
    ev = {e.key: e.value for e in findings[1].evidence}
    assert "hunter2" not in ev["network_activity"]  # redacted
    assert "1.2.3.4" in ev["network_activity"]  # non-secret content preserved


def test_query_telemetry_ignores_result_stream_metadata_objects():
    # lc.query returns a STREAM of result objects: timeline/facets/timeseries
    # (rows=None) alongside the events object (rows=[...]). Only real events count —
    # the metadata objects must not become junk findings or inflate events_total.
    stream = [
        {"searchresultid": "1", "type": "timeline", "rows": None},
        {"searchresultid": "2", "type": "facets", "facets": [], "rows": None},
        {"type": "events", "rows": [
            {"data": {"event/NETWORK_ACTIVITY": [{"DESTINATION": {"IP_ADDRESS": "20.1.1.1"}}]}},
        ]},
    ]
    lc = FakeClient(query=stream)
    findings = tools.query_telemetry(lc, hunt="network_connections")
    ev0 = {e.key: e.value for e in findings[0].evidence}
    assert ev0["events_total"] == "1"  # only the real event, not the 2 metadata objects
    assert len(findings) == 1 + 1
    ev1 = {e.key: e.value for e in findings[1].evidence}
    assert "20.1.1.1" in ev1["network_activity"]
    titles = " ".join(f.title for f in findings).lower()
    assert "timeline" not in titles and "searchresult" not in titles


def test_query_telemetry_domain_filter_routes_to_dns_anchored():
    # "does host connect to microsoft.com" -> DNS_REQUEST filtered by domain, since
    # NETWORK_CONNECTIONS carries IPs not domains. Boundary-anchored (exact apex OR a
    # proper subdomain), NOT a bare `contains`, so a lookalike (microsoft.com.evil.net)
    # does NOT match. (`is`/`ends with`/`or` confirmed valid in the LCQL query filter.)
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    lc = _Cap(find_sensor=[{"sid": "s1", "hostname": "web-01.corp.local", "is_online": True}])
    tools.query_telemetry(lc, hostname="web-01", domain="microsoft.com")
    q = captured["lcql"]
    assert "DNS_REQUEST" in q
    assert 'event/DOMAIN_NAME is "microsoft.com"' in q
    assert 'event/DOMAIN_NAME ends with ".microsoft.com"' in q
    assert 'contains "microsoft.com"' not in q  # anchored, not substring — no lookalike FPs
    assert 'hostname == "web-01.corp.local"' in q  # resolved, dot-boundary-safe


def test_query_telemetry_domain_strips_leading_wildcard():
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    tools.query_telemetry(_Cap(), domain="*.microsoft.com")
    q = captured["lcql"]
    assert 'is "microsoft.com"' in q  # leading "*." stripped to the base domain
    assert 'ends with ".microsoft.com"' in q


def test_query_telemetry_domain_rejects_injection():
    lc = FakeClient(query=[{"rows": []}])
    findings = tools.query_telemetry(lc, domain='x" | evil')
    assert findings[0].finding_type.value == "posture"
    assert "domain" in findings[0].title.lower()


def test_query_telemetry_bare_wildcard_domain_falls_back_to_preset():
    # domain="*." (or bare "*") strips to empty -> must NOT become contains "" (which
    # matches every DNS record); fall back to the preset instead.
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    for d in ("*.", "*"):
        tools.query_telemetry(_Cap(), hunt="new_processes", domain=d)
        assert "NEW_PROCESS" in captured["lcql"], f"domain={d!r} should fall back to preset"
        assert 'contains ""' not in captured["lcql"]


def test_query_telemetry_empty_domain_falls_back_to_preset():
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": []}]

    tools.query_telemetry(_Cap(), hunt="new_processes", domain="")
    assert "NEW_PROCESS" in captured["lcql"]  # empty domain -> normal preset, not DNS


def test_query_telemetry_never_blank_title():
    # An empty-string first projection must not yield a blank title.
    lc = FakeClient(query=[{"rows": [{"data": {"event/FILE_PATH": ""}}]}])
    findings = tools.query_telemetry(lc, hunt="new_processes")
    assert findings[1].title == "telemetry event"


def test_query_telemetry_redacts_secret_named_scalar_projection():
    # A scalar under a secret-NAMED projection field must also be redacted: the field
    # name becomes the VALUE of Evidence.key, so the boundary redact_obj (which keys
    # off dict keys 'key'/'value') can't key-hint-redact it. Redact at the data level.
    lc = FakeClient(query=[{"rows": [{"data": {
        "event/CLIENT_SECRET": "hunter2", "event/FILE_PATH": "C:\\ok.exe"}}]}])
    findings = tools.query_telemetry(lc, hunt="new_processes")
    ev = {e.key: e.value for e in findings[1].evidence}
    assert "hunter2" not in ev["client_secret"]  # redacted
    assert ev["file_path"] == "C:\\ok.exe"  # non-secret preserved


def test_query_telemetry_lcql_override_does_not_mislabel_scope():
    # Raw lcql override ignores hostname for the query, so it must not label scope by it.
    lc = FakeClient(query=[{"rows": [{"data": {"event/DOMAIN_NAME": "x"}}]}])
    findings = tools.query_telemetry(
        lc, hostname="h1", lcql='-1h | * | DNS_REQUEST | * | event/DOMAIN_NAME'
    )
    assert "on h1" not in findings[0].title
    assert findings[0].entity is None


def test_query_telemetry_lcql_override():
    captured = {}

    class _Cap(FakeClient):
        def query(self, lcql, start, end, limit=50):
            captured["lcql"] = lcql
            return [{"rows": [{"data": {"event/DOMAIN_NAME": "evil.com"}}]}]

    findings = tools.query_telemetry(_Cap(), lcql="-1h | * | DNS_REQUEST | * | event/DOMAIN_NAME")
    assert "DNS_REQUEST" in captured["lcql"]  # raw lcql passed through, not a preset
    assert findings[0].finding_type.value == "hunt_result"


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


def test_get_org_overview_reports_sleeper_census():
    # Live org: 1,173 of 1,247 sensors are lc:sleeper-dormant — the single most
    # important posture fact about that fleet. The overview must surface it.
    lc = FakeClient(
        sensors=[{"sid": "s1", "is_online": True}, {"sid": "s2", "is_online": True}],
        tag_count=1,
    )
    findings = tools.get_org_overview(lc)
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["sensors_dormant_sleepers"] == "1"


def test_get_org_overview_survives_tag_census_failure():
    lc = FakeClient(
        sensors=[{"sid": "s1", "is_online": True}],
        raise_on={"count_sensors_with_tag": PermissionDeniedError("denied")},
    )
    findings = tools.get_org_overview(lc)
    assert findings[0].finding_type.value == "posture"  # overview still renders
    assert "sensors_dormant_sleepers" not in {e.key for e in findings[0].evidence}


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


@pytest.mark.asyncio
async def test_open_passthrough_params_stay_free_strings():
    from f0_limacharlie_mcp import server
    tools_by_name = {t.name: t for t in await server.mcp.list_tools()}
    assert "enum" not in tools_by_name["list_detections"].inputSchema["properties"]["category"]
    assert "enum" not in tools_by_name["list_dr_rules"].inputSchema["properties"]["namespace"]
