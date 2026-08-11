"""Contract tests for the Sentinel tools (fake client, no network)."""
from __future__ import annotations

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


async def test_hunt_firewall_time_predicate_comes_first(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []})
    await tools.hunt_firewall(client, hours=6)
    kql = [q for q in client.queries if CEF in q][0]
    body = kql.split("|", 1)[1]
    assert body.strip().startswith("where TimeGenerated > ago(")


async def test_hunt_firewall_clamps_hours_to_retention(fake):
    client = fake(rows={USAGE: _TABLES, CEF: []}, retention_days=30)
    await tools.hunt_firewall(client, hours=99999)
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


async def test_hunt_dns_web_missing_umbrella_table_returns_posture(fake):
    client = fake(rows={USAGE: [{"DataType": "CommonSecurityLog", "GB": 1.0}]})
    out = await tools.hunt_dns_web(client, surface="dns")
    assert len(out) == 1 and out[0].finding_type.value == "posture"
