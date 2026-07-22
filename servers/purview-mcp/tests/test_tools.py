"""Contract tests for the Purview tools.

Tools take the core GraphClient; tests pass a fake (no network). Real field
names / serviceSource enum values are validated by the live smoke test.
"""
from __future__ import annotations

import pytest
from f0_purview_mcp import tools
from f0_sectools_core.auth.graph import GraphError

DLP_ALERT = {
    "id": "al1",
    "title": "DLP policy match: Financial data external share",
    "severity": "high",
    "status": "new",
    "category": "dataLossPrevention",
    "serviceSource": "dataLossPrevention",
    "createdDateTime": "2026-07-20T10:00:00Z",
    "actorDisplayName": None,
}
IRM_ALERT = {
    "id": "al2",
    "title": "Potential data theft by departing user",
    "severity": "medium",
    "status": "inProgress",
    "serviceSource": "microsoftInsiderRiskManagement",
    "createdDateTime": "2026-07-19T09:00:00Z",
}


class FakeGC:
    """Canned GET/POST responses keyed by path substring; records calls."""

    def __init__(self, gets=None, posts=None, raise_on=None):
        self._gets = gets or {}
        self._posts = posts or {}
        self._raise = raise_on or {}
        self.calls: list[tuple[str, str, dict | None]] = []

    def _match(self, table, path):
        for key, value in table.items():
            if key in path:
                return value
        return {"value": []}

    async def get(self, path, params=None):
        self.calls.append(("GET", path, params))
        for key, status in self._raise.items():
            if key in path:
                raise GraphError(status, "boom")
        return self._match(self._gets, path)

    async def post(self, path, json_body):
        self.calls.append(("POST", path, json_body))
        for key, status in self._raise.items():
            if key in path:
                raise GraphError(status, "boom")
        return self._match(self._posts, path)


# ---------- DLP summary ----------

@pytest.mark.asyncio
async def test_dlp_summary_rolls_up_by_severity_and_status():
    gc = FakeGC(gets={"alerts_v2": {"value": [DLP_ALERT, {**DLP_ALERT, "id": "al3",
                                                          "severity": "low",
                                                          "status": "resolved"}]}})
    findings = await tools.get_dlp_summary(gc)
    assert findings[0].finding_type.value == "posture"
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["alerts_total"] == "2"
    assert "high: 1" in ev["by_severity"] and "low: 1" in ev["by_severity"]
    assert "new: 1" in ev["by_status"]


@pytest.mark.asyncio
async def test_dlp_summary_zero_alerts_names_possible_causes():
    gc = FakeGC()
    findings = await tools.get_dlp_summary(gc)
    assert "0" in findings[0].title
    action = findings[0].recommended_action.summary.lower()
    assert "polic" in action or "licens" in action  # quiet OR not-configured/licensed


@pytest.mark.asyncio
async def test_dlp_summary_filters_by_service_source_and_time():
    gc = FakeGC()
    await tools.get_dlp_summary(gc, hours_back=24)
    _, path, params = gc.calls[0]
    filt = (params or {}).get("$filter", "")
    assert "serviceSource" in filt and "createdDateTime ge " in filt


@pytest.mark.asyncio
async def test_dlp_summary_headline_severity_is_case_insensitive():
    # Review #62 nit: the max() key compared raw strings; a mixed-case "High"
    # silently misranked the rollup headline.
    gc = FakeGC(gets={"alerts_v2": {"value": [
        {**DLP_ALERT, "severity": "High"},
        {**DLP_ALERT, "id": "x", "severity": "low"},
    ]}})
    findings = await tools.get_dlp_summary(gc)
    assert findings[0].severity.value == "high"


# ---------- DLP alert list ----------

@pytest.mark.asyncio
async def test_list_dlp_alerts_maps_alert_findings():
    gc = FakeGC(gets={"alerts_v2": {"value": [DLP_ALERT]}})
    findings = await tools.list_dlp_alerts(gc)
    assert findings[0].finding_type.value == "alert"
    assert "Financial data" in findings[0].title
    assert findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_list_dlp_alerts_severity_min_filters():
    gc = FakeGC(gets={"alerts_v2": {"value": [DLP_ALERT,
                                              {**DLP_ALERT, "id": "x", "severity": "low"}]}})
    findings = await tools.list_dlp_alerts(gc, severity_min="high")
    assert len(findings) == 1 and findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_list_dlp_alerts_tolerates_informational_and_missing_severity():
    # Graph's real severity enum includes 'informational'/'unknown' (our own
    # _sev() maps them); a chained-if comprehension evaluated .index() BEFORE
    # the membership filter and crashed on them (CC review, PR #62). They must
    # be silently excluded from the floor filter, never raise.
    gc = FakeGC(gets={"alerts_v2": {"value": [
        DLP_ALERT,
        {**DLP_ALERT, "id": "i1", "severity": "informational"},
        {**DLP_ALERT, "id": "i2", "severity": None},
    ]}})
    findings = await tools.list_dlp_alerts(gc, severity_min="low")
    assert len(findings) == 1 and findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_list_dlp_alerts_bounded_with_more_note():
    alerts = [{**DLP_ALERT, "id": str(i)} for i in range(30)]
    gc = FakeGC(gets={"alerts_v2": {"value": alerts}})
    findings = await tools.list_dlp_alerts(gc, limit=5)
    assert len(findings) == 5 + 1  # bounded + "more available" note
    assert "more" in findings[-1].title.lower()


@pytest.mark.asyncio
async def test_dlp_permission_missing_degrades():
    gc = FakeGC(raise_on={"alerts_v2": 403})
    findings = await tools.list_dlp_alerts(gc)
    assert findings[0].finding_type.value == "posture"
    assert "permission" in findings[0].title.lower() or "not granted" in findings[0].title.lower()


# ---------- Insider risk ----------

@pytest.mark.asyncio
async def test_list_insider_risk_alerts_uses_irm_source():
    gc = FakeGC(gets={"alerts_v2": {"value": [IRM_ALERT]}})
    findings = await tools.list_insider_risk_alerts(gc)
    _, _, params = gc.calls[0]
    assert "InsiderRisk" in (params or {}).get("$filter", "")
    assert findings[0].finding_type.value == "alert"
    assert "departing user" in findings[0].title


# ---------- Sensitivity labels ----------

@pytest.mark.asyncio
async def test_list_sensitivity_labels_inventory():
    gc = FakeGC(gets={"sensitivityLabels": {"value": [
        {"id": "l1", "name": "Confidential", "isActive": True, "priority": 2},
        {"id": "l2", "name": "Public", "isActive": True, "priority": 0},
    ]}})
    findings = await tools.list_sensitivity_labels(gc)
    titles = " ".join(f.title for f in findings)
    assert "Confidential" in titles and "Public" in titles
    # beta endpoint is called with an absolute URL (GraphClient passes it through)
    assert any("beta" in path for _, path, _ in gc.calls)


@pytest.mark.asyncio
async def test_list_sensitivity_labels_empty_flags_no_classification():
    gc = FakeGC()
    findings = await tools.list_sensitivity_labels(gc)
    assert findings[0].finding_type.value == "posture"
    assert "no sensitivity labels" in findings[0].title.lower()


# ---------- Audit search (async two-phase) ----------

_QUERY_DONE = {"id": "q-123", "status": "succeeded"}
_RECORDS = {"value": [
    {"id": "r1", "operation": "FileDeleted", "userPrincipalName": "jsmith@corp.local",
     "service": "SharePoint", "createdDateTime": "2026-07-21T08:00:00Z",
     "objectId": "https://corp.sharepoint.com/x.docx"},
]}


@pytest.mark.asyncio
async def test_search_audit_log_completes_and_maps_records(monkeypatch):
    monkeypatch.setattr(tools.asyncio, "sleep", _no_sleep)
    gc = FakeGC(posts={"auditLog/queries": {"id": "q-123", "status": "notStarted"}},
                gets={"records": _RECORDS, "queries/q-123": _QUERY_DONE})
    findings = await tools.search_audit_log(gc, activity="FileDeleted")
    body = gc.calls[0][2]
    assert body["operationFilters"] == ["FileDeleted"]
    assert any(f.finding_type.value == "hunt_result" and "FileDeleted" in f.title
               for f in findings)


@pytest.mark.asyncio
async def test_search_audit_log_still_running_returns_query_id(monkeypatch):
    monkeypatch.setattr(tools.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(tools, "_POLL_DEADLINE_S", 0.01)
    gc = FakeGC(posts={"auditLog/queries": {"id": "q-9", "status": "notStarted"}},
                gets={"queries/q-9": {"id": "q-9", "status": "running"}})
    findings = await tools.search_audit_log(gc, user="jsmith@corp.local")
    assert findings[0].finding_type.value == "posture"
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["audit_query_id"] == "q-9"
    assert "get_audit_results" in findings[0].recommended_action.summary


@pytest.mark.asyncio
async def test_search_audit_log_rejects_unsafe_filters():
    gc = FakeGC()
    for kwargs in ({"activity": 'x"; drop'}, {"user": "a b|c"}):
        findings = await tools.search_audit_log(gc, **kwargs)
        assert findings[0].finding_type.value == "posture"
        assert gc.calls == []  # never submitted


@pytest.mark.asyncio
async def test_get_audit_results_fetches_completed_query():
    gc = FakeGC(gets={"records": _RECORDS, "queries/q-123": _QUERY_DONE})
    findings = await tools.get_audit_results(gc, "q-123")
    assert any("FileDeleted" in f.title for f in findings)
    assert any("jsmith@corp.local" in str(e.value) for f in findings for e in f.evidence)


@pytest.mark.asyncio
async def test_get_audit_results_block_polls_until_ready(monkeypatch):
    # A small model has no timer, so it re-polls get_audit_results back-to-back
    # (live opencode run: 5 polls in ~4s). get_audit_results must block-poll like
    # search_audit_log — each call consumes real time and catches completion
    # mid-poll instead of returning "notStarted" instantly.
    monkeypatch.setattr(tools.asyncio, "sleep", _no_sleep)
    statuses = iter([{"status": "notStarted"}, {"status": "running"}, _QUERY_DONE])

    class _Prog(FakeGC):
        async def get(self, path, params=None):
            self.calls.append(("GET", path, params))
            if "records" in path:
                return _RECORDS
            return next(statuses)

    gc = _Prog()
    findings = await tools.get_audit_results(gc, "q-123")
    # It polled more than once (block-poll), then returned real records.
    status_gets = [c for c in gc.calls if c[0] == "GET" and "records" not in c[1]]
    assert len(status_gets) >= 2
    assert any("FileDeleted" in f.title for f in findings)


@pytest.mark.asyncio
async def test_get_audit_results_pending_after_deadline_tells_user_to_wait(monkeypatch):
    monkeypatch.setattr(tools.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(tools, "_POLL_DEADLINE_S", 0.01)
    gc = FakeGC(gets={"queries/q-9": {"id": "q-9", "status": "notStarted"}})
    findings = await tools.get_audit_results(gc, "q-9")
    assert findings[0].finding_type.value == "posture"
    action = findings[0].recommended_action.summary.lower()
    assert "minutes" in action and "wait" in action


@pytest.mark.asyncio
async def test_get_audit_results_running_says_retry(monkeypatch):
    monkeypatch.setattr(tools.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(tools, "_POLL_DEADLINE_S", 0.01)
    gc = FakeGC(gets={"queries/q-9": {"id": "q-9", "status": "running"}})
    findings = await tools.get_audit_results(gc, "q-9")
    assert "running" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_get_audit_results_rejects_unsafe_id():
    gc = FakeGC()
    findings = await tools.get_audit_results(gc, "q/../etc")
    assert findings[0].finding_type.value == "posture"
    assert gc.calls == []


@pytest.mark.asyncio
async def test_search_audit_log_reuses_inflight_identical_search(monkeypatch):
    # Live opencode run: the model resubmitted the SAME search when results
    # weren't ready, spawning a new ~15-min server-side query each time. An
    # identical search (same filters/window) within the reuse TTL must NOT
    # POST again — it re-checks the existing query instead.
    monkeypatch.setattr(tools.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(tools, "_POLL_DEADLINE_S", 0.01)
    gc = FakeGC(posts={"auditLog/queries": {"id": "q-1", "status": "notStarted"}},
                gets={"queries/q-1": {"id": "q-1", "status": "running"}})
    first = await tools.search_audit_log(gc, activity="FileDeleted")
    posts = [c for c in gc.calls if c[0] == "POST"]
    assert len(posts) == 1
    second = await tools.search_audit_log(gc, activity="FileDeleted")
    posts = [c for c in gc.calls if c[0] == "POST"]
    assert len(posts) == 1, "identical search must reuse the in-flight query, not resubmit"
    ev = {e.key: e.value for e in second[0].evidence}
    assert ev["audit_query_id"] == "q-1"
    assert {e.key: e.value for e in first[0].evidence}["audit_query_id"] == "q-1"


@pytest.mark.asyncio
async def test_pending_finding_surfaces_the_queried_window(monkeypatch):
    # A reused search returns results for the ORIGINAL window, not "last
    # hours_back from now" — surface the actual queried window so the caller
    # knows what the eventual results cover (CC review #63).
    monkeypatch.setattr(tools.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(tools, "_POLL_DEADLINE_S", 0.01)
    gc = FakeGC(posts={"auditLog/queries": {"id": "q-w", "status": "notStarted"}},
                gets={"queries/q-w": {"id": "q-w", "status": "running"}})
    first = await tools.search_audit_log(gc, activity="FileDeleted", hours_back=4)
    ev1 = {e.key: e.value for e in first[0].evidence}
    assert "window" in ev1 and "T" in ev1["window"]  # an ISO range
    # Reuse: same window reported, not a freshly recomputed one.
    second = await tools.search_audit_log(gc, activity="FileDeleted", hours_back=4)
    ev2 = {e.key: e.value for e in second[0].evidence}
    assert ev2["window"] == ev1["window"]


@pytest.mark.asyncio
async def test_search_audit_log_different_filters_submit_fresh(monkeypatch):
    monkeypatch.setattr(tools.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(tools, "_POLL_DEADLINE_S", 0.01)
    gc = FakeGC(posts={"auditLog/queries": {"id": "q-2", "status": "notStarted"}},
                gets={"queries": {"id": "q-2", "status": "running"}})
    await tools.search_audit_log(gc, activity="FileDeleted")
    await tools.search_audit_log(gc, activity="FileDownloaded")
    posts = [c for c in gc.calls if c[0] == "POST"]
    assert len(posts) == 2  # different filters = genuinely new search


@pytest.mark.asyncio
async def test_pending_finding_sets_honest_expectations(monkeypatch):
    # "in a minute or two" misled the model into resubmitting; the guidance
    # must state the real latency class and forbid resubmission.
    monkeypatch.setattr(tools.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(tools, "_POLL_DEADLINE_S", 0.01)
    gc = FakeGC(posts={"auditLog/queries": {"id": "q-3", "status": "notStarted"}},
                gets={"queries/q-3": {"id": "q-3", "status": "running"}})
    findings = await tools.search_audit_log(gc, user="jsmith@corp.local")
    action = findings[0].recommended_action.summary.lower()
    # Honest latency + explicit "stop polling this turn" (the model was hammering).
    assert "minutes" in action and "stop polling" in action
    assert "again in this turn" in action


@pytest.mark.asyncio
async def test_search_audit_log_failed_terminal_state(monkeypatch):
    # Review #62 coverage gap: the failed/cancelled terminal branch.
    monkeypatch.setattr(tools.asyncio, "sleep", _no_sleep)
    gc = FakeGC(posts={"auditLog/queries": {"id": "q-4", "status": "notStarted"}},
                gets={"queries/q-4": {"id": "q-4", "status": "failed"}})
    findings = await tools.search_audit_log(gc, activity="FileDeleted")
    assert findings[0].finding_type.value == "posture"
    assert "failed" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_audit_permission_missing_degrades():
    gc = FakeGC(raise_on={"auditLog": 403})
    findings = await tools.search_audit_log(gc)
    assert findings[0].finding_type.value == "posture"
    assert "auditlogsquery" in (findings[0].title + str(findings[0].evidence)).lower() \
        or "permission" in findings[0].title.lower()


async def _no_sleep(_):
    return None


# ---------- Server schema ----------

@pytest.mark.asyncio
async def test_server_advertises_enums_and_six_tools():
    from f0_purview_mcp import server
    tools_by_name = {t.name: t for t in await server.mcp.list_tools()}
    assert len(tools_by_name) == 6
    sev = tools_by_name["list_dlp_alerts"].inputSchema["properties"]["severity_min"]
    assert set(sev.get("enum", [])) == {"low", "medium", "high"}
