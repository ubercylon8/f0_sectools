"""Contract tests for the Sentinel tools (fake client, no network)."""
from __future__ import annotations

import pytest
from f0_sectools_core.auth.graph import GraphError
from f0_sentinel_mcp import probe, tools

USAGE = "Usage"
_TABLES = [
    {"DataType": "CommonSecurityLog", "GB": 250.45},
    {"DataType": "Cisco_Umbrella_dns_CL", "GB": 2.8},
    {"DataType": "OfficeActivity", "GB": 4.1},
    {"DataType": "SecurityIncident", "GB": 0.0},
]


async def test_probe_returns_table_names_with_gb(fake):
    client = fake(rows={USAGE: _TABLES})
    assert await probe.probed_tables(client) == {
        "CommonSecurityLog": 250.45,
        "Cisco_Umbrella_dns_CL": 2.8,
        "OfficeActivity": 4.1,
        "SecurityIncident": 0.0,
    }


async def test_probe_defaults_missing_or_non_numeric_gb_to_zero(fake):
    # A row missing GB, or carrying a non-numeric GB, must still register the
    # table as ingesting -- it must not raise and must not drop the table.
    rows = [
        {"DataType": "WeirdTable"},
        {"DataType": "OtherTable", "GB": "not-a-number"},
    ]
    client = fake(rows={USAGE: rows})
    assert await probe.probed_tables(client) == {"WeirdTable": 0.0, "OtherTable": 0.0}


async def test_probe_is_cached_for_the_process(fake):
    client = fake(rows={USAGE: _TABLES})
    await probe.probed_tables(client)
    await probe.probed_tables(client)
    assert len([q for q in client.queries if "Usage" in q]) == 1


async def test_require_table_returns_none_when_present(fake):
    client = fake(rows={USAGE: _TABLES})
    assert await probe.require_table(client, "CommonSecurityLog", "firewall (CEF)") is None


async def test_require_table_returns_posture_not_empty_list_when_absent(fake):
    # An empty list reads as "no matching traffic". "This workspace has no
    # firewall feed" is a materially different answer and must be said out loud.
    client = fake(rows={USAGE: _TABLES})
    f = await probe.require_table(client, "Syslog", "syslog")
    assert f is not None
    assert f.finding_type.value == "posture"
    assert "syslog" in f.title.lower()


async def test_list_data_sources_returns_one_finding_per_table_plus_summary(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.list_data_sources(client)
    titles = " ".join(f.title for f in out)
    assert "CommonSecurityLog" in titles
    assert any(f.finding_type.value == "posture" for f in out)


async def test_list_data_sources_labels_families(fake):
    # A per-table mapping keyed by table name, not a collapsed dict -- collapsing
    # would keep only the last table's family and let a set-membership assertion
    # pass even if `_family()` always returned the "custom" fallback. Includes one
    # table (MyVendorCustomTable_CL) that legitimately has no prefix match, so the
    # "custom" fallback is pinned deliberately rather than passing by accident.
    rows = [*_TABLES, {"DataType": "MyVendorCustomTable_CL", "GB": 1.0}]
    client = fake(rows={USAGE: rows})
    out = await tools.list_data_sources(client)
    fam = {
        f.entity.id: e.value
        for f in out
        if f.entity is not None
        for e in f.evidence
        if e.key == "family"
    }
    assert fam["CommonSecurityLog"] == "firewall"
    assert fam["Cisco_Umbrella_dns_CL"] == "dns_web"
    assert fam["OfficeActivity"] == "office"
    assert fam["SecurityIncident"] == "incident"
    assert fam["MyVendorCustomTable_CL"] == "custom"


def test_family_labels_cisco_umbrella_firewall_as_firewall_not_dns_web():
    # Cisco_Umbrella_firewall_CL starts with "Cisco_Umbrella", so the generic
    # dns_web entry matches it before any firewall-specific entry -- unless
    # the more specific prefix is checked first. No hunt_* tool queries this
    # table either way; this only fixes the label list_data_sources shows.
    assert tools._family("Cisco_Umbrella_firewall_CL") == "firewall"


async def test_list_data_sources_sorts_by_gb_descending(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.list_data_sources(client)
    per_table = [f for f in out if f.entity is not None and f.entity.id != "sentinel"]
    assert [f.entity.id for f in per_table] == [
        "CommonSecurityLog", "OfficeActivity", "Cisco_Umbrella_dns_CL", "SecurityIncident",
    ]


async def test_list_data_sources_carries_gb_evidence(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.list_data_sources(client)
    gb_by_table = {
        f.entity.id: e.value
        for f in out
        if f.entity is not None
        for e in f.evidence
        if e.key == "gb_30d"
    }
    assert gb_by_table["CommonSecurityLog"] == "250.45"


async def test_list_data_sources_maps_403_to_posture(fake):
    client = fake(raise_on={USAGE: GraphError(403, "forbidden")})
    out = await tools.list_data_sources(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"


def _many_tables(count: int) -> list[dict[str, object]]:
    # Descending GB so the sort order is unambiguous.
    return [{"DataType": f"Table{i:03d}_CL", "GB": float(count - i)} for i in range(count)]


async def test_list_data_sources_default_limit_bounds_output(fake):
    # This is the tool every other tool's description names as the first
    # call; on a large enterprise workspace (200-400 tables) an unbounded dump
    # is a context flood.
    client = fake(rows={USAGE: _many_tables(40)})
    out = await tools.list_data_sources(client)
    per_table = [f for f in out if f.entity is not None and f.entity.id != "sentinel"]
    assert len(per_table) == 25


async def test_list_data_sources_respects_custom_limit(fake):
    client = fake(rows={USAGE: _many_tables(40)})
    out = await tools.list_data_sources(client, limit=5)
    per_table = [f for f in out if f.entity is not None and f.entity.id != "sentinel"]
    assert len(per_table) == 5


async def test_list_data_sources_flags_more_available_when_truncated(fake):
    client = fake(rows={USAGE: _many_tables(40)})
    out = await tools.list_data_sources(client)
    assert any(
        f.title.lower().startswith("showing") or "more" in f.title.lower() for f in out
    )


async def test_list_data_sources_no_truncation_marker_when_everything_shown(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.list_data_sources(client)
    assert not any(
        f.title.lower().startswith("showing") or "more results available" in f.title.lower()
        for f in out
    )


CEF = "CommonSecurityLog"


async def test_hunt_firewall_without_indicator_is_aggregate_only(fake):
    # 112M rows/7d: an unfiltered row dump is a cost and context-window incident.
    client = fake(rows={
        USAGE: _TABLES,
        CEF: [{"DeviceAction": "Drop", "DestinationPort": 445, "Events": 900}],
    })
    out = await tools.hunt_firewall(client, action="blocked")
    kql = [q for q in client.queries if CEF in q][0]
    assert "summarize" in kql
    assert "| take" not in kql.split("summarize")[0]
    assert out and all(f.finding_type.value in {"hunt_result", "posture"} for f in out)


async def test_hunt_firewall_with_indicator_samples_rows(fake):
    client = fake(rows={
        USAGE: _TABLES,
        CEF: [{"TimeGenerated": "2026-08-11T00:00:00Z", "SourceIP": "10.1.2.3",
               "DestinationIP": "8.8.8.8", "DestinationPort": 53, "DeviceAction": "Accept"}],
    })
    out = await tools.hunt_firewall(client, indicator="10.1.2.3")
    kql = [q for q in client.queries if CEF in q][0]
    assert '"10.1.2.3"' in kql
    assert "summarize" not in kql
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_hunt_firewall_indicator_mode_kql_ends_with_bounded_take(fake):
    # The row-mode (indicator supplied) output bound is otherwise completely
    # untested -- deleting clamp_limit or the `| take {limit}` clause here
    # leaves every other test green on a table carrying ~112M rows/7d.
    client = fake(rows={USAGE: _TABLES, CEF: []})
    await tools.hunt_firewall(client, indicator="10.1.2.3", limit=7)
    kql = [q for q in client.queries if CEF in q][0]
    # limit + 1: one spare row makes "was there more?" a fact rather than the
    # `len(rows) >= limit` guess, which over-reports on an exactly-full page.
    assert kql.rstrip().endswith("| take 8")


async def test_hunt_firewall_indicator_mode_clamps_huge_limit(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []})
    await tools.hunt_firewall(client, indicator="10.1.2.3", limit=100000)
    kql = [q for q in client.queries if CEF in q][0]
    # Clamped to MAX_LIMIT (100), then one spare row for truncation detection.
    # The extra row is fetched, never shown -- the cap on returned findings holds.
    assert kql.rstrip().endswith("| take 101")


async def test_hunt_firewall_time_predicate_comes_first(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []})
    await tools.hunt_firewall(client, hours_back=6)
    kql = [q for q in client.queries if CEF in q][0]
    body = kql.split("|", 1)[1]
    assert body.strip().startswith("where TimeGenerated > ago(")


async def test_hunt_firewall_clamps_hours_to_retention(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []}, retention_days=30)
    await tools.hunt_firewall(client, hours_back=99999)
    kql = [q for q in client.queries if CEF in q][0]
    assert "ago(720h)" in kql


async def test_hunt_firewall_rejects_domain_indicator(fake):
    # RequestURL fill rate is 0.08% on this table — a domain filter returns
    # nothing, so say so instead of answering "no activity found".
    client = fake(rows={USAGE: _TABLES, CEF: []})
    out = await tools.hunt_firewall(client, indicator="evil.com")
    assert len(out) == 1
    assert out[0].finding_type.value == "posture"
    ra = out[0].recommended_action
    assert "hunt_dns_web" in (ra.summary if ra else "")


async def test_hunt_firewall_missing_table_returns_posture(fake):
    client = fake(rows={USAGE: [{"DataType": "Syslog", "GB": 1.0}]})
    out = await tools.hunt_firewall(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert "firewall" in out[0].title.lower()


async def test_hunt_firewall_action_blocked_maps_to_vendor_values(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []})
    await tools.hunt_firewall(client, action="blocked")
    kql = [q for q in client.queries if CEF in q][0]
    assert "Drop" in kql and "Accept" not in kql


async def test_hunt_firewall_bad_action_reports_rather_than_ignoring(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []})
    out = await tools.hunt_firewall(client, action="allowedd")
    assert len(out) == 1 and out[0].finding_type.value == "posture"


async def test_hunt_firewall_429_maps_to_rate_limited(fake):
    client = fake(rows={USAGE: _TABLES}, raise_on={CEF: GraphError(429, "slow down")})
    out = await tools.hunt_firewall(client)
    assert len(out) == 1 and "Rate limited" in out[0].title


DNS = "Cisco_Umbrella_dns_CL"
WEB = "Cisco_Umbrella_proxy_CL"


async def test_hunt_dns_web_selects_table_by_surface(fake):
    client = fake(rows={USAGE: _TABLES + [{"DataType": WEB, "GB": 0.9}], DNS: [], WEB: []})
    await tools.hunt_dns_web(client, surface="dns")
    await tools.hunt_dns_web(client, surface="web")
    assert any(DNS in q for q in client.queries)
    assert any(WEB in q for q in client.queries)


async def test_hunt_dns_web_filters_ingested_header_rows(fake):
    # Action_s == "Action" is a CSV header the connector ingested as data.
    client = fake(rows={USAGE: _TABLES, DNS: []})
    await tools.hunt_dns_web(client, surface="dns")
    kql = [q for q in client.queries if DNS in q][0]
    assert '!in~ ("Action")' in kql


async def test_hunt_dns_web_accepts_domain_indicator(fake):
    client = fake(rows={USAGE: _TABLES, DNS: [{"Domain_s": "evil.com", "Action_s": "Blocked"}]})
    out = await tools.hunt_dns_web(client, surface="dns", indicator="evil.com", action="blocked")
    kql = [q for q in client.queries if DNS in q][0]
    assert '"evil.com"' in kql and "Blocked" in kql
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_hunt_dns_web_rejects_kql_injection_in_indicator(fake):
    client = fake(rows={USAGE: _TABLES, DNS: []})
    out = await tools.hunt_dns_web(client, surface="dns", indicator='x" | project *; //')
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert not [q for q in client.queries if DNS in q]


async def test_hunt_dns_web_bad_surface_reports(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.hunt_dns_web(client, surface="carrier-pigeon")
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert "dns" in (out[0].recommended_action.summary if out[0].recommended_action else "")


async def test_hunt_dns_web_action_unsupported_on_surface_is_rejected(fake):
    # "detected" is a member of the GLOBAL action vocabulary (n.ACTIONS,
    # because hunt_firewall's CEF table supports it) but the dns surface's
    # action_map only has allowed/blocked. action_clause() would silently
    # no-op for an unrecognized action and return ALL traffic while the
    # caller believes it filtered -- this must be rejected, not dropped.
    client = fake(rows={USAGE: _TABLES, DNS: []})
    out = await tools.hunt_dns_web(client, surface="dns", action="detected")
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert not [q for q in client.queries if DNS in q]


async def test_hunt_dns_web_missing_umbrella_table_returns_posture(fake):
    client = fake(rows={USAGE: [{"DataType": "CommonSecurityLog", "GB": 1.0}]})
    out = await tools.hunt_dns_web(client, surface="dns")
    assert len(out) == 1 and out[0].finding_type.value == "posture"


VPN = "Cisco_Umbrella_ravpnlogs_CL"


async def test_hunt_dns_web_vpn_filters_ingested_csv_header_rows(fake):
    # Live-verified 2026-08-11: Event_Type_s == "Event Type" is the CSV
    # header ingested as data, ~762 rows/7d alongside 10742 "Connected".
    client = fake(rows={USAGE: [*_TABLES, {"DataType": VPN, "GB": 0.5}], VPN: []})
    await tools.hunt_dns_web(client, surface="vpn")
    kql = [q for q in client.queries if VPN in q][0]
    assert '!in~ ("Event Type")' in kql


async def test_hunt_dns_web_vpn_action_allowed_maps_to_capitalised_connected(fake):
    # Real Event_Type_s values are capitalised ("Connected"/"Failed"), not
    # lowercase -- the lowercase guess only ever matched by luck via `in~`'s
    # case-insensitivity.
    client = fake(rows={USAGE: [*_TABLES, {"DataType": VPN, "GB": 0.5}], VPN: []})
    await tools.hunt_dns_web(client, surface="vpn", action="allowed")
    kql = [q for q in client.queries if VPN in q][0]
    assert "Connected" in kql and "connected" not in kql


async def test_hunt_dns_web_vpn_action_blocked_maps_to_capitalised_failed(fake):
    client = fake(rows={USAGE: [*_TABLES, {"DataType": VPN, "GB": 0.5}], VPN: []})
    await tools.hunt_dns_web(client, surface="vpn", action="blocked")
    kql = [q for q in client.queries if VPN in q][0]
    assert "Failed" in kql and "failed" not in kql


OA = "OfficeActivity"


async def test_search_office_activity_without_operation_returns_operation_breakdown(fake):
    # Discovery in ONE call: the model learns valid operation names instead of
    # guessing them, which is the two-call dance purview's audit search forces.
    client = fake(rows={USAGE: _TABLES, OA: [{"Operation": "FileDownloaded", "Events": 48163}]})
    out = await tools.search_office_activity(client)
    kql = [q for q in client.queries if OA in q][0]
    assert "summarize" in kql and "by Operation" in kql
    assert any("FileDownloaded" in f.title for f in out)


async def test_search_office_activity_with_operation_returns_events(fake):
    client = fake(rows={USAGE: _TABLES, OA: [
        {"TimeGenerated": "2026-08-11T00:00:00Z", "Operation": "FileDownloaded",
         "UserId": "a@b.com", "OfficeWorkload": "OneDrive"},
    ]})
    out = await tools.search_office_activity(client, operation="FileDownloaded")
    kql = [q for q in client.queries if OA in q][0]
    assert 'Operation =~ "FileDownloaded"' in kql
    assert "summarize" not in kql
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_search_office_activity_workload_filter(fake):
    client = fake(rows={USAGE: _TABLES, OA: []})
    await tools.search_office_activity(client, workload="exchange", operation="MailItemsAccessed")
    kql = [q for q in client.queries if OA in q][0]
    assert 'OfficeWorkload =~ "Exchange"' in kql


async def test_search_office_activity_teams_workload_maps_to_microsoftteams(fake):
    # Live-verified 2026-08-11: OfficeWorkload's Teams value is the string
    # "MicrosoftTeams", NOT "Teams" -- pinned explicitly since it is exactly
    # the kind of live-measured string a well-meaning refactor "corrects"
    # into breakage without a dedicated test.
    client = fake(rows={USAGE: _TABLES, OA: []})
    await tools.search_office_activity(client, workload="teams", operation="MessageSent")
    kql = [q for q in client.queries if OA in q][0]
    assert 'OfficeWorkload =~ "MicrosoftTeams"' in kql
    assert 'OfficeWorkload =~ "Teams"' not in kql


async def test_search_office_activity_any_workload_emits_no_workload_filter(fake):
    client = fake(rows={USAGE: _TABLES, OA: []})
    await tools.search_office_activity(client, workload="any", operation="FileAccessed")
    kql = [q for q in client.queries if OA in q][0]
    assert "OfficeWorkload =~" not in kql


async def test_search_office_activity_user_filter_validated(fake):
    client = fake(rows={USAGE: _TABLES, OA: []})
    ok = await tools.search_office_activity(client, user="a@b.com", operation="FileAccessed")
    assert not (len(ok) == 1 and ok[0].title.startswith("Unsupported"))
    # The `user` filter must actually reach the KQL, not just pass validation
    # and then get silently dropped -- a dropped filter would return everyone's
    # activity, formatted identically, with nothing signalling the loss.
    kql = [q for q in client.queries if OA in q][0]
    assert 'UserId =~ "a@b.com"' in kql
    bad = await tools.search_office_activity(client, user='a" or 1==1')
    assert len(bad) == 1 and bad[0].finding_type.value == "posture"


async def test_search_office_activity_bad_workload_reports(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.search_office_activity(client, workload="yammer")
    assert len(out) == 1 and out[0].finding_type.value == "posture"


async def test_search_office_activity_missing_table_returns_posture(fake):
    client = fake(rows={USAGE: [{"DataType": "Syslog", "GB": 1.0}]})
    out = await tools.search_office_activity(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"


SI = "SecurityIncident"
# Real SecurityIncident shape (live-verified 2026-08-11): there is NO
# `Tactics` column. Tactics/techniques live inside `AdditionalData`, a JSON
# STRING (not a nested object -- the fixture must encode that or a test can
# pass against a shape the platform never sends). `Owner` is likewise a JSON
# string, commonly all-null on an unassigned incident. Values below are
# fabricated placeholders, not real tenant data.
_INC = [{
    "IncidentNumber": 4211, "Title": "Exfiltration incident", "Severity": "High",
    "Status": "New",
    "Owner": '{"objectId":null,"email":null,"assignedTo":null,"userPrincipalName":null}',
    "AdditionalData": (
        '{"alertsCount":1,"bookmarksCount":0,"commentsCount":0,'
        '"alertProductNames":["Microsoft Defender Advanced Threat Protection"],'
        '"tactics":["Exfiltration"],"techniques":["T1041"],'
        '"providerIncidentUrl":"https://contoso.example/incident/4211"}'
    ),
    "TimeGenerated": "2026-08-10T12:00:00Z",
    "IncidentUrl": "https://contoso.example/incident/4211",
}]


async def test_list_sentinel_incidents_returns_incident_findings(fake):
    client = fake(rows={USAGE: _TABLES, SI: _INC})
    out = await tools.list_sentinel_incidents(client)
    assert any(f.finding_type.value == "incident" for f in out)
    assert any("Exfiltration incident" in f.title for f in out)


async def test_list_sentinel_incidents_surfaces_mitre_tactics(fake):
    # Tactics are what this view adds over f0-defender.list_incidents. There
    # is no `Tactics` column on SecurityIncident -- this must come from
    # parsing the `AdditionalData` JSON string. Reverting the extraction to
    # `r.get("Tactics")` must make this test fail (see task-15 mutation
    # evidence): the fixture carries no such key, by construction.
    client = fake(rows={USAGE: _TABLES, SI: _INC})
    out = await tools.list_sentinel_incidents(client)
    ev = {e.key: e.value for f in out for e in f.evidence}
    assert "tactics" in ev and "Exfiltration" in ev["tactics"]


async def test_list_sentinel_incidents_surfaces_mitre_techniques(fake):
    client = fake(rows={USAGE: _TABLES, SI: _INC})
    out = await tools.list_sentinel_incidents(client)
    ev = {e.key: e.value for f in out for e in f.evidence}
    assert "techniques" in ev and "T1041" in ev["techniques"]


async def test_list_sentinel_incidents_owner_all_null_reports_unassigned(fake):
    # Live shape: {"objectId":null,"email":null,"assignedTo":null,
    # "userPrincipalName":null}. The raw blob must never be emitted.
    client = fake(rows={USAGE: _TABLES, SI: _INC})
    out = await tools.list_sentinel_incidents(client)
    ev = {e.key: e.value for f in out for e in f.evidence}
    assert ev["owner"] == "unassigned"
    assert "objectId" not in ev["owner"]
    assert "null" not in ev["owner"]


async def test_list_sentinel_incidents_owner_parses_assigned_display_name(fake):
    assigned = [{
        **_INC[0],
        "Owner": '{"objectId":"11111111-1111-1111-1111-111111111111","email":null,'
        '"assignedTo":"Jane Analyst","userPrincipalName":null}',
    }]
    client = fake(rows={USAGE: _TABLES, SI: assigned})
    out = await tools.list_sentinel_incidents(client)
    ev = {e.key: e.value for f in out for e in f.evidence}
    assert ev["owner"] == "Jane Analyst"


# --- Defensive JSON parsing: AdditionalData/Owner may be absent, empty,
# malformed, or already-a-dict. None of those may raise; every non-object
# outcome must degrade to an empty/safe value.

def test_parse_json_object_passes_through_an_already_deserialized_dict():
    assert tools._parse_json_object({"tactics": ["Impact"]}) == {"tactics": ["Impact"]}


def test_parse_json_object_none_and_empty_string_yield_empty_dict():
    assert tools._parse_json_object(None) == {}
    assert tools._parse_json_object("") == {}


def test_parse_json_object_malformed_json_does_not_raise():
    assert tools._parse_json_object("{not valid json") == {}


def test_parse_json_object_non_object_json_yields_empty_dict():
    # Valid JSON that isn't an object (a bare list/number/string) must not be
    # handed back as-is -- callers assume a dict and would crash on .get().
    assert tools._parse_json_object("[1, 2, 3]") == {}
    assert tools._parse_json_object("42") == {}


def test_incident_tactics_techniques_absent_additionaldata_is_empty():
    assert tools._incident_tactics_techniques(None) == ("", "")
    assert tools._incident_tactics_techniques("") == ("", "")


def test_incident_tactics_techniques_malformed_json_is_empty_not_raising():
    assert tools._incident_tactics_techniques("{broken") == ("", "")


def test_incident_owner_absent_or_malformed_falls_back_to_unassigned():
    assert tools._incident_owner(None) == "unassigned"
    assert tools._incident_owner("") == "unassigned"
    assert tools._incident_owner("{broken") == "unassigned"


async def test_list_sentinel_incidents_severity_min_filters(fake):
    # severity_min is a FLOOR, not an exact match: "medium" must include
    # medium and everything above it (high) while excluding everything below
    # (low, informational). Using "high" here (the top of the range) cannot
    # distinguish a floor from an exact-match bug -- both pass identically.
    client = fake(rows={USAGE: _TABLES, SI: []})
    await tools.list_sentinel_incidents(client, severity_min="medium")
    kql = [q for q in client.queries if SI in q][0]
    assert "Medium" in kql and "High" in kql and "Low" not in kql
    assert "Informational" not in kql


async def test_list_sentinel_incidents_status_filter(fake):
    client = fake(rows={USAGE: _TABLES, SI: []})
    await tools.list_sentinel_incidents(client, status="new")
    kql = [q for q in client.queries if SI in q][0]
    assert 'Status =~ "New"' in kql


async def test_list_sentinel_incidents_status_any_emits_no_status_filter(fake):
    client = fake(rows={USAGE: _TABLES, SI: []})
    await tools.list_sentinel_incidents(client, status="any")
    kql = [q for q in client.queries if SI in q][0]
    assert "Status =~" not in kql


async def test_list_sentinel_incidents_deduplicates_by_incident_number(fake):
    # SecurityIncident appends a NEW ROW on every incident update, so a naive
    # list shows the same incident many times.
    client = fake(rows={USAGE: _TABLES, SI: []})
    await tools.list_sentinel_incidents(client)
    kql = [q for q in client.queries if SI in q][0]
    assert "arg_max(TimeGenerated, *) by IncidentNumber" in kql


async def test_list_sentinel_incidents_bad_severity_reports(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.list_sentinel_incidents(client, severity_min="catastrophic")
    assert len(out) == 1 and out[0].finding_type.value == "posture"


async def test_list_sentinel_incidents_missing_table_returns_posture(fake):
    client = fake(rows={USAGE: [{"DataType": "Syslog", "GB": 1.0}]})
    out = await tools.list_sentinel_incidents(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"


# Shaped after the live finding: one Fusion rule (Microsoft's built-in
# correlation rule) carrying a dozen tactics on its own, plus a handful of
# genuinely custom Scheduled rules that only ever tag two tactics between
# them. If a change ever counts Fusion as "custom", `rules_custom` and
# `tactics_covered_custom` below both catch it. Also carries a
# MicrosoftSecurityIncidentCreation rule (Microsoft-managed, imports
# Defender/MCAS alerts -- not Fusion, but equally not operator-authored) and
# a DISABLED rule tagging a tactic ("Reconnaissance") no enabled rule
# carries, so the built-in-classification and enabled-only-aggregation fixes
# are both actually exercised rather than merely plausible.
_FUSION_TACTICS = [
    "InitialAccess", "Persistence", "PrivilegeEscalation", "DefenseEvasion",
    "CredentialAccess", "Discovery", "LateralMovement", "Collection",
    "CommandAndControl", "Exfiltration", "Impact", "Execution",
]
_RULES = [
    {"kind": "Fusion", "name": "BuiltInFusion",
     "properties": {"displayName": "Advanced Multistage Attack Detection",
     "enabled": True, "severity": "High", "tactics": _FUSION_TACTICS}},
    # Microsoft-managed (imports Defender/MCAS alerts), NOT Fusion-kind --
    # exercises the broadened `_BUILTIN_RULE_KINDS` classification. Tags
    # Execution, which only Fusion also tags -- no genuinely custom rule
    # does -- so a misclassification leaks straight into tactics_covered_custom.
    {"kind": "MicrosoftSecurityIncidentCreation", "name": "defender-incident-import",
     "properties": {"displayName": "Create incidents based on Microsoft security alerts",
     "enabled": True, "severity": "Informational", "tactics": ["InitialAccess", "Execution"]}},
    {"kind": "Scheduled", "name": "custom-defense-evasion-1",
     "properties": {"displayName": "Disabling Security Services",
     "enabled": True, "severity": "Medium", "tactics": ["DefenseEvasion"]}},
    {"kind": "Scheduled", "name": "custom-defense-evasion-2",
     "properties": {"displayName": "Suspicious Registry Modification",
     "enabled": True, "severity": "Medium", "tactics": ["DefenseEvasion"]}},
    {"kind": "Scheduled", "name": "custom-initial-access-1",
     "properties": {"displayName": "Impossible Travel Sign-in",
     "enabled": True, "severity": "High", "tactics": ["InitialAccess"]}},
    {"kind": "Scheduled", "name": "custom-initial-access-2",
     "properties": {"displayName": "New Country Sign-in",
     "enabled": True, "severity": "Medium", "tactics": ["InitialAccess"]}},
    # DISABLED. Reconnaissance is not tagged by any enabled rule (Fusion's 12
    # tactics stop at Execution/Persistence/etc -- Reconnaissance is one of
    # the two ATT&CK tactics nothing here enables) -- this rule detects
    # nothing today, so its tactic must never count as covered.
    {"kind": "Scheduled", "name": "retired-rule",
     "properties": {"displayName": "Retired rule",
     "enabled": False, "severity": "Low", "tactics": ["Reconnaissance"]}},
]


async def test_get_detection_coverage_summarizes_rules(fake):
    client = fake(arm={"alertRules": _RULES})
    out = await tools.get_detection_coverage(client)
    summary = out[0]
    ev = {e.key: e.value for e in summary.evidence}
    assert ev["rules_total"] == "7"
    assert ev["rules_enabled"] == "6"
    assert ev["rules_custom"] == "5"


async def test_get_detection_coverage_treats_microsoft_incident_creation_as_builtin(fake):
    # MicrosoftSecurityIncidentCreation imports Defender/MCAS alerts as
    # incidents through Microsoft's own logic, not the operator's -- counting
    # it as custom overstates coverage the same way un-fixed Fusion did.
    # Reverting `_is_builtin_rule` to Fusion-only must make this fail: the
    # rule would then count as custom, `rules_custom` would rise from 5 to 6,
    # and "Execution" (which no genuinely custom rule tags) would leak into
    # tactics_covered_custom.
    client = fake(arm={"alertRules": _RULES})
    out = await tools.get_detection_coverage(client)
    ev = {e.key: e.value for e in out[0].evidence}
    assert ev["rules_custom"] == "5"
    assert "Execution" not in ev["tactics_covered_custom"].split(", ")


async def test_get_detection_coverage_ignores_disabled_rules_tactics(fake):
    # retired-rule is DISABLED and tags Reconnaissance -- a disabled rule
    # detects nothing, so Reconnaissance must stay uncovered (both overall
    # and for custom rules) despite a rule technically carrying that tag.
    # Reverting the aggregation loop to iterate `rules` instead of `enabled`
    # must make this fail: Reconnaissance would then show up as covered.
    client = fake(arm={"alertRules": _RULES})
    out = await tools.get_detection_coverage(client)
    ev = {e.key: e.value for e in out[0].evidence}
    assert "Reconnaissance" not in ev["tactics_covered_all"].split(", ")
    assert "Reconnaissance" in ev["tactics_uncovered_all"].split(", ")
    assert "Reconnaissance" in ev["tactics_uncovered_custom"].split(", ")


async def test_get_detection_coverage_distinguishes_builtin_from_custom(fake):
    # This distinction is the whole fix: the live workspace showed "12 of 14
    # tactics covered" overall while its own (non-Fusion) rules covered only
    # DefenseEvasion and InitialAccess. Counting the Fusion rule as custom
    # coverage must make this test fail (see task-15 mutation evidence).
    client = fake(arm={"alertRules": _RULES})
    out = await tools.get_detection_coverage(client)
    summary = out[0]
    ev = {e.key: e.value for e in summary.evidence}
    assert ev["tactics_covered_custom"] == "DefenseEvasion, InitialAccess"
    assert len(ev["tactics_covered_all"].split(", ")) == 12
    assert "Persistence" in ev["tactics_uncovered_custom"]
    # Persistence IS covered overall (by Fusion) -- it must not appear in the
    # "uncovered_all" list even though it's absent from every custom rule.
    assert "Persistence" not in ev["tactics_uncovered_all"].split(", ")
    assert "2 of 14 MITRE tactics covered by custom rules" in summary.title


async def test_get_detection_coverage_names_uncovered_tactics(fake):
    # Naming the GAP for custom rules is the whole value: the incident queue
    # cannot show it, and a coverage figure padded by Fusion hides it.
    client = fake(arm={"alertRules": _RULES})
    out = await tools.get_detection_coverage(client)
    summary = out[0]
    ev = {e.key: e.value for e in summary.evidence}
    # Persistence is tagged only by the Fusion rule -- absent from every
    # custom rule -- so it must show up in tactics_uncovered_custom's VALUE,
    # not merely because the evidence key happens to be named that.
    assert "Persistence" in ev["tactics_uncovered_custom"]
    assert summary.recommended_action is not None
    assert "Persistence" in summary.recommended_action.summary


async def test_get_detection_coverage_without_arm_config_returns_posture(fake):
    client = fake(has_arm=False)
    out = await tools.get_detection_coverage(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert "SENTINEL_SUBSCRIPTION_ID" in (
        out[0].recommended_action.summary if out[0].recommended_action else ""
    )


async def test_get_detection_coverage_403_names_sentinel_reader(fake):
    client = fake(raise_on={"alertRules": GraphError(403, "forbidden")})
    out = await tools.get_detection_coverage(client)
    assert len(out) == 1
    assert "Microsoft Sentinel Reader" in (
        out[0].recommended_action.summary if out[0].recommended_action else ""
    )


async def test_get_detection_coverage_no_rules_is_a_finding_not_silence(fake):
    client = fake(arm={"alertRules": []})
    out = await tools.get_detection_coverage(client)
    assert len(out) >= 1
    assert "0" in out[0].title or "no" in out[0].title.lower()


def _many_rules(count: int) -> list[dict[str, object]]:
    return [
        {"kind": "Scheduled", "name": f"rule-{i}",
         "properties": {"displayName": f"Rule {i}", "enabled": True,
                         "severity": "Low", "tactics": ["InitialAccess"]}}
        for i in range(count)
    ]


async def test_get_detection_coverage_caps_per_rule_findings(fake):
    # The per-rule findings are supplementary detail, capped separately from
    # the summary finding, which already carries the aggregate counts.
    client = fake(arm={"alertRules": _many_rules(40)})
    out = await tools.get_detection_coverage(client)
    rule_findings = [f for f in out if f.title.startswith("Rule:")]
    assert len(rule_findings) == 25
    assert any(
        f.title.lower().startswith("showing") or "more" in f.title.lower() for f in out
    )


async def test_run_kql_passes_query_through(fake):
    client = fake(rows={"Heartbeat": [{"Computer": "srv-1"}]})
    out = await tools.run_kql(client, "Heartbeat | project Computer")
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_run_kql_appends_bound_when_query_has_none(fake):
    client = fake(rows={"Heartbeat": []})
    await tools.run_kql(client, "Heartbeat | project Computer", limit=10)
    assert "| take 11" in client.queries[0]  # limit + 1 spare, as above


async def test_run_kql_respects_an_existing_bound(fake):
    client = fake(rows={"Heartbeat": []})
    await tools.run_kql(client, "Heartbeat | take 5")
    assert client.queries[0].count("take") == 1


async def test_run_kql_force_bound_survives_a_trailing_line_comment(fake):
    # "Heartbeat // note" + " | take 25" used to become "Heartbeat // note |
    # take 25" -- the bound silently commented out, so the query dispatched
    # unbounded. Model-written KQL carries trailing `//` comments routinely.
    client = fake(rows={"Heartbeat": []})
    await tools.run_kql(client, "Heartbeat // note", limit=25)
    dispatched = client.queries[0]
    # The bound must be live KQL, not part of the comment: on its own line,
    # after the comment, not appended to the same commented-out line.
    assert dispatched.count("take") == 1
    lines = dispatched.split("\n")
    take_line = next(line for line in lines if "take" in line)
    assert "//" not in take_line
    assert "| take 26" in take_line


async def test_run_kql_rejects_control_commands(fake):
    client = fake(rows={})
    for bad in (".create table X", ".drop table X", ".set-or-append Y", ".ingest inline"):
        out = await tools.run_kql(client, bad)
        assert len(out) == 1 and out[0].finding_type.value == "posture", bad
    assert client.queries == []


async def test_run_kql_rejects_empty_query(fake):
    client = fake(rows={})
    out = await tools.run_kql(client, "   ")
    assert len(out) == 1 and out[0].finding_type.value == "posture"


async def test_run_kql_semantic_error_returns_reason(fake):
    client = fake(raise_on={"Bogus": GraphError(400, "SemanticError: Failed to resolve 'Nope'")})
    out = await tools.run_kql(client, "Bogus | project Nope")
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert "Nope" in out[0].title


_LEADING_NONPRINTABLE = (
    "\x00",  # NUL (C0 control)
    "\x01",  # SOH (C0 control)
    "\x08",  # BS  (C0 control)
    "\x0e",  # SO  (C0 control)
    "\x1b",  # ESC (C0 control)
    "\x7f",  # DEL
    "\x9f",  # APC (C1 control)
    "﻿",  # BOM / zero-width no-break space
    "​",  # zero-width space
    "⁠",  # word joiner
)


async def test_run_kql_rejects_control_command_hidden_by_nonprintable_prefix(fake):
    # str.strip() only removes ordinary whitespace. Both Unicode format chars
    # (BOM, zero-width space, word joiner -- category Cf) and C0/C1 control
    # characters (NUL, ESC, DEL, ... -- category Cc) survive it and can hide a
    # dot-prefixed control command from a naive "strip then check dot prefix"
    # guard. The fix is a whitelist (query[0].isprintable()), not a blacklist
    # of categories discovered one PoC at a time -- exercise the whole class,
    # not just the two characters that were first found to bypass it.
    client = fake(rows={})
    for ch in _LEADING_NONPRINTABLE:
        for bad in (f"{ch}.drop table X", f"{ch}.set-or-append Y", f" \n\t{ch}.ingest inline"):
            out = await tools.run_kql(client, bad)
            assert len(out) == 1 and out[0].finding_type.value == "posture", repr(bad)
        assert client.queries == [], repr(ch)


async def test_run_kql_ordinary_queries_still_dispatch(fake):
    # The nonprintable-prefix guard must not regress into rejecting valid
    # input: a plain query, and one with only ordinary leading whitespace,
    # must both still reach client.query.
    client = fake(rows={"Heartbeat": [{"Computer": "srv-1"}]})
    out = await tools.run_kql(client, "Heartbeat | take 5")
    assert client.queries == ["Heartbeat | take 5"]
    assert any(f.finding_type.value == "hunt_result" for f in out)

    client2 = fake(rows={"Heartbeat": [{"Computer": "srv-1"}]})
    out2 = await tools.run_kql(client2, "   \n\t Heartbeat | take 5")
    assert client2.queries == ["Heartbeat | take 5"]
    assert any(f.finding_type.value == "hunt_result" for f in out2)


async def test_run_kql_rejects_control_command_on_a_later_line(fake):
    # Issue #99: the guard used to check only the whole-string prefix
    # (query.startswith(".")), so a dot-command on a second line reached
    # client.query() -- "print 1\n.show diagnostics" is not itself a
    # dot-prefixed string, but its second line is a control command.
    client = fake(rows={})
    for bad in (
        "print 1\n.show diagnostics",
        "Heartbeat | take 1\n.drop table X",
        "print 1\n\n.drop table X",  # blank line between must not confuse it
    ):
        out = await tools.run_kql(client, bad)
        assert len(out) == 1 and out[0].finding_type.value == "posture", bad
    assert client.queries == []


async def test_run_kql_rejects_control_command_on_a_later_line_hidden_by_nonprintable(fake):
    # Same vector as above, but the offending line's dot is additionally
    # hidden behind a leading invisible/control character -- the per-line
    # hardening must match what the whole-query check already does.
    client = fake(rows={})
    for ch in _LEADING_NONPRINTABLE:
        bad = f"print 1\n{ch}.drop table X"
        out = await tools.run_kql(client, bad)
        assert len(out) == 1 and out[0].finding_type.value == "posture", repr(bad)
    assert client.queries == []


async def test_run_kql_ordinary_multiline_query_still_dispatches(fake):
    # The per-line guard must not regress into rejecting valid multi-line
    # KQL -- e.g. a query broken across lines for readability.
    client = fake(rows={"Heartbeat": [{"Computer": "srv-1"}]})
    out = await tools.run_kql(client, "Heartbeat\n| summarize count()\n| take 5")
    assert client.queries == ["Heartbeat\n| summarize count()\n| take 5"]
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_run_kql_query_with_comment_line_still_dispatches(fake):
    # A `//` line comment (on its own line) must not be mistaken for a
    # control command -- "/" is printable and is not the dot prefix.
    client = fake(rows={"Heartbeat": [{"Computer": "srv-1"}]})
    query = "Heartbeat\n// filter placeholder\n| take 5"
    out = await tools.run_kql(client, query)
    assert client.queries == [query]
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_run_kql_decimal_literal_on_a_continuation_line_still_dispatches(fake):
    # Review follow-up on #99: KQL is whitespace-insensitive across an
    # unterminated expression, so a decimal literal opening a continuation
    # line ("| where Ratio >" then "    .5") is legal KQL -- a bare "starts
    # with dot" check over-rejects it. A dot only counts as a control-command
    # prefix when immediately followed by a letter.
    client = fake(rows={"Heartbeat": [{"Computer": "srv-1"}]})
    query = "Heartbeat\n| where Ratio >\n    .5\n| take 5"
    out = await tools.run_kql(client, query)
    assert client.queries == [query]
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_run_kql_dot_line_inside_verbatim_string_now_rejected(fake):
    # This is a deliberate, documented FALSE REJECTION, not a regression. A
    # Kusto verbatim string literal (```...```) can span multiple lines, e.g.
    # an embedded multi-line sample log whose body happens to open with
    # ".example" -- legal KQL. An earlier version of this guard tried to
    # track ``` fences so it could exempt exactly this line. That fence
    # tracking was computed from the caller's own query and activated over
    # caller-controlled lines, so it was itself a repeatedly-exploited
    # bypass (see the comment above `_line_control_command_reason`) and was
    # removed with no replacement. Every line is now classified at face
    # value, so this exotic-but-legal query is rejected. The guard prefers
    # refusing a rare legal query over ever dispatching a control command.
    client = fake(rows={})
    query = "print s = ```\n.example log line\n```\n| take 5"
    out = await tools.run_kql(client, query)
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert client.queries == []


async def test_run_kql_control_command_after_a_closed_verbatim_string_still_blocks(fake):
    # There is no ``` fence handling at all anymore -- backtick lines are
    # ordinary text to this guard. A control command on a line after some
    # backtick-fenced text is still just a line starting with a dot-letter
    # sequence and must still be rejected.
    client = fake(rows={})
    query = "print s = ```\nx\n```\n.drop table X"
    out = await tools.run_kql(client, query)
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert client.queries == []


async def test_run_kql_dot_followed_by_non_letter_is_never_a_control_command(fake):
    # Narrower unit-level check on the classifier's boundary: a dot at the
    # start of a line is only a control-command prefix when followed by a
    # letter. A trailing lone "." (nothing after it) and "." followed by
    # another "." must both still dispatch.
    for query in ("Heartbeat\n.\n| take 5", "Heartbeat\n..\n| take 5"):
        c = fake(rows={"Heartbeat": [{"Computer": "srv-1"}]})
        out = await tools.run_kql(c, query)
        assert c.queries == [query], query
        assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_run_kql_appending_a_fence_to_a_command_does_not_evade_the_guard(fake):
    # Historical regression: earlier versions of this guard tried to treat
    # ``` as a meaningful delimiter, and appending a stray fence to a
    # control command could exempt the whole line. There is no fence
    # handling left at all now -- a trailing ``` is just ordinary trailing
    # text and has no effect on classification.
    client = fake(rows={})
    for bad in (
        ".drop table X ```",
        "print 1\n.drop table X ```",
        "print 1\n.drop table X ```y```",
    ):
        out = await tools.run_kql(client, bad)
        assert len(out) == 1 and out[0].finding_type.value == "posture", bad
    assert client.queries == []


async def test_run_kql_unclosed_verbatim_block_disables_the_exemption(fake):
    # An unclosed ``` fence used to matter for the (now-removed) exemption's
    # bookkeeping. It has no meaning to this guard anymore -- the fence line
    # is ordinary text, and ".drop table X" on the following line is
    # classified at face value, same as always.
    client = fake(rows={})
    out = await tools.run_kql(client, "``` \n.drop table X")
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert client.queries == []


async def test_run_kql_balanced_inline_block_still_blocks_trailing_command(fake):
    # A ``` pair opening and closing on one line is, again, just ordinary
    # text to this guard -- the command on the next line is classified at
    # face value and must still be rejected.
    client = fake(rows={})
    out = await tools.run_kql(client, "```x``` \n.drop table X")
    assert len(out) == 1 and out[0].finding_type.value == "posture"
    assert client.queries == []


async def test_run_kql_let_statement_before_query_still_dispatches(fake):
    # A `let` statement is semicolon-terminated, ordinary legal KQL -- must
    # not be affected by the control-command guard at all.
    client = fake(rows={"Heartbeat": [{"Computer": "srv-1"}]})
    query = "let x = 1;\nHeartbeat | take x"
    out = await tools.run_kql(client, query)
    assert client.queries == [query]
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_run_kql_trailing_comment_before_a_new_take_line_still_dispatches(fake):
    # A same-line trailing "// note" comment followed by an explicit
    # "| take N" on the NEXT line is ordinary, already-bounded KQL and must
    # not be affected by the control-command guard at all.
    client = fake(rows={"Heartbeat": [{"Computer": "srv-1"}]})
    query = "Heartbeat // note\n| take 5"
    out = await tools.run_kql(client, query)
    assert client.queries == [query]
    assert any(f.finding_type.value == "hunt_result" for f in out)


async def test_run_kql_confirmed_bypasses_are_now_blocked(fake):
    # Regression lock for the three-times-broken verbatim-string exemption
    # (removed above): every one of these confirmed the exemption could be
    # made to hide a real control command, either behind a fence that is
    # inert to the Kusto engine (inside a `//` comment or a quoted string
    # literal) or behind whitespace/invisible characters the old
    # "dot immediately followed by a letter" check didn't tolerate. With the
    # exemption gone and the classifier closed up, every one must be
    # rejected before dispatch.
    client = fake(rows={})
    zwsp = "​"  # zero-width space (category Cf)
    bom = "﻿"  # BOM / zero-width no-break space (category Cf)
    bad_queries = (
        # Fence hidden inside a `//` line comment -- inert to Kusto, but the
        # old exemption still counted it and treated the line in between as
        # exempt verbatim-string content.
        "// ```\n.drop table X\n// ```",
        # Fence hidden inside quoted string literals on their own lines --
        # again inert to Kusto's own string parsing, but still counted by
        # the old `query.count("```")` check.
        'print s = "```"\n.drop table X\nprint t = "```"',
        # Fence trailing a same-line comment, control command on the next
        # line.
        "Heartbeat | take 1 // ```\n.drop table VictimTable\n// ```",
        # Same comment-fence trick, with the control-command line itself
        # additionally hidden behind a leading zero-width space -- this used
        # to defeat the nonprintable-prefix branch too, because the old
        # exemption skipped classifying the line at all.
        f"// ```\n{zwsp}.drop table X\n// ```",
        # Whitespace/invisible characters between the dot and the command
        # name -- the classifier must skip these, not treat them as
        # disqualifying.
        ". drop table X",
        ".\tdrop table X",
        f".{zwsp}drop table X",
        # A trailing fence appended to a single-line command.
        ".drop table X ```",
        # A control command on a later line, no fences involved at all.
        "print 1\n.drop table X",
        ".create table X",
        # A later-line control command additionally hidden behind a BOM.
        f"print 1\n{bom}.drop table X",
        # A control command shape not covered by the other literal-command
        # test above.
        ".ingest inline into table X <| 1",
    )
    for bad in bad_queries:
        out = await tools.run_kql(client, bad)
        assert len(out) == 1 and out[0].finding_type.value == "posture", repr(bad)
    assert client.queries == []


# --- Critical Rule: every tool returns a finding, never an exception, on a
# platform error. `require_table` (-> `probed_tables` -> `client.query`) is a
# real transport call and can raise `GraphError` exactly like any other query
# -- a tool that awaits it OUTSIDE its own try/except lets that exception
# escape past tools.py, past server.py's `_render`, and past redaction. This
# is fault injection at the transport boundary, not a single call site: it
# forces the error on EVERY query the fake client can receive (raise_on={"":
# err} matches every substring) and on the ARM `alertRules` resource, so a
# regression in ANY of the four `require_table`-based tools is caught, not
# just the one call site a narrower test happened to hit.

_ALL_SEVEN_TOOLS = {
    "list_data_sources": lambda c: tools.list_data_sources(c),
    "hunt_firewall": lambda c: tools.hunt_firewall(c),
    "hunt_dns_web": lambda c: tools.hunt_dns_web(c),
    "search_office_activity": lambda c: tools.search_office_activity(c),
    "list_sentinel_incidents": lambda c: tools.list_sentinel_incidents(c),
    "get_detection_coverage": lambda c: tools.get_detection_coverage(c),
    "run_kql": lambda c: tools.run_kql(c, "Heartbeat | take 5"),
}


@pytest.mark.parametrize("status", [401, 403, 429])
@pytest.mark.parametrize("tool_name", sorted(_ALL_SEVEN_TOOLS))
async def test_every_tool_returns_finding_not_exception_on_graph_error(fake, tool_name, status):
    err = GraphError(status, "boom")
    # "" is a substring of every KQL string the fake client's query() sees, so
    # this fails EVERY query call regardless of which table is asked for;
    # "alertRules" additionally covers get_detection_coverage's ARM call.
    client = fake(raise_on={"": err, "alertRules": err}, has_arm=True)
    out = await _ALL_SEVEN_TOOLS[tool_name](client)
    assert isinstance(out, list) and len(out) >= 1
    assert all(f.finding_type.value == "posture" for f in out), (tool_name, status)


# --- Read-tool audit (2026-07-25 framework) applied to sentinel, server #9 ---
# Q2: can already-handled records come back as current?  Q4: is truncation
# disclosed?  Both were live-confirmed on the validation workspace: the default
# queue returned 23 Closed + 2 New while only 2 incidents were actually open,
# and 25 of 55 deduped incidents were dropped with no disclosure.

def _incidents(n, status="New"):
    return [dict(_INC[0], IncidentNumber=4000 + i, Status=status) for i in range(n)]


async def test_incident_queue_excludes_closed_by_default(fake):
    """A SOC queue is open work. Closed incidents are not the analyst's queue."""
    client = fake(rows={USAGE: _TABLES, SI: _INC})
    await tools.list_sentinel_incidents(client)
    kql = client.queries[-1]
    assert 'Status !~ "Closed"' in kql


async def test_incident_queue_status_any_still_includes_closed(fake):
    """The old behaviour stays reachable -- it just stops being the default."""
    client = fake(rows={USAGE: _TABLES, SI: _INC})
    await tools.list_sentinel_incidents(client, status="any")
    assert "Closed" not in client.queries[-1]


async def test_incident_queue_status_closed_is_still_selectable(fake):
    client = fake(rows={USAGE: _TABLES, SI: _INC})
    await tools.list_sentinel_incidents(client, status="closed")
    assert 'Status =~ "Closed"' in client.queries[-1]


async def test_incident_queue_discloses_truncation(fake):
    client = fake(rows={USAGE: _TABLES, SI: _incidents(6)})
    out = await tools.list_sentinel_incidents(client, limit=5)
    assert sum(f.finding_type.value == "incident" for f in out) == 5
    assert any("more results available" in f.title for f in out)


async def test_incident_queue_silent_when_nothing_hidden(fake):
    client = fake(rows={USAGE: _TABLES, SI: _incidents(5)})
    out = await tools.list_sentinel_incidents(client, limit=5)
    assert not any("more results available" in f.title for f in out)


async def test_office_activity_discloses_truncation(fake):
    rows = [{"Operation": f"Op{i}", "TimeGenerated": "2026-08-10T12:00:00Z"} for i in range(6)]
    client = fake(rows={USAGE: _TABLES, OA: rows})
    out = await tools.search_office_activity(client, operation="FileDownloaded", limit=5)
    assert any("more results available" in f.title for f in out)


async def test_run_kql_discloses_truncation(fake):
    rows = [{"Computer": f"host{i}"} for i in range(6)]
    client = fake(rows={USAGE: _TABLES, "Heartbeat": rows})
    out = await tools.run_kql(client, "Heartbeat", limit=5)
    assert any("more results available" in f.title for f in out)


# --- hunt_firewall: perimeter + cloud ------------------------------------
UFW = "Cisco_Umbrella_firewall_CL"


async def test_hunt_firewall_still_defaults_to_the_perimeter_table(fake):
    """Adding a surface must not move the default out from under existing callers."""
    client = fake(rows={USAGE: _TABLES, CEF: []})
    await tools.hunt_firewall(client)
    assert any(CEF in q for q in client.queries)
    assert not any(UFW in q for q in client.queries)


async def test_hunt_firewall_cloud_surface_queries_the_umbrella_table(fake):
    client = fake(rows={USAGE: _TABLES + [{"DataType": UFW, "GB": 12.3}], UFW: []})
    await tools.hunt_firewall(client, surface="cloud")
    assert any(UFW in q for q in client.queries)


async def test_hunt_firewall_rejects_an_unknown_surface(fake):
    client = fake(rows={USAGE: _TABLES})
    out = await tools.hunt_firewall(client, surface="datacenter")
    assert "surface" in out[0].title
    assert not any(CEF in q or UFW in q for q in client.queries)


async def test_hunt_firewall_cloud_searches_identity(fake):
    client = fake(rows={USAGE: _TABLES + [{"DataType": UFW, "GB": 12.3}], UFW: []})
    await tools.hunt_firewall(client, surface="cloud", indicator="someone@example.gob.do")
    kql = [q for q in client.queries if UFW in q][0]
    assert 'Identity_s has "someone@example.gob.do"' in kql


async def test_hunt_firewall_perimeter_still_rejects_an_identity_indicator(fake):
    """The CEF table carries usernames on 0.14% of rows; it is IP/port only."""
    client = fake(rows={USAGE: _TABLES, CEF: []})
    out = await tools.hunt_firewall(client, indicator="someone@example.gob.do")
    assert "indicator" in out[0].title


async def test_aggregate_mode_discloses_truncation(fake):
    """`top {limit}` can never return more than limit, so has_more was always
    False — the row path was fixed but the aggregate path kept truncating
    silently. cloud_firewall has 286 distinct identities against a default
    limit of 25, so a bare call hides 261 users without saying so."""
    client = fake(rows={USAGE: _TABLES + [{"DataType": UFW, "GB": 1.0}], UFW: []})
    await tools.hunt_firewall(client, surface="cloud", limit=5)
    kql = [q for q in client.queries if UFW in q][0]
    # Asserted on the emitted KQL, not on rows the fake hands back: the fake
    # returns its canned list whatever the query says, so a row-count assertion
    # here would pass against the very bug it is meant to catch.
    assert "| top 6 by Events desc" in kql, "aggregate must fetch limit + 1 too"


async def test_aggregate_mode_silent_when_nothing_hidden(fake):
    rows = [{"verdict_s": "ALLOW", "Identity_s": f"user{i}", "Events": 9 - i} for i in range(5)]
    client = fake(rows={USAGE: _TABLES + [{"DataType": UFW, "GB": 1.0}], UFW: rows})
    out = await tools.hunt_firewall(client, surface="cloud", limit=5)
    assert not any("more results available" in f.title for f in out)
    assert sum(f.finding_type.value == "hunt_result" for f in out) == 5
