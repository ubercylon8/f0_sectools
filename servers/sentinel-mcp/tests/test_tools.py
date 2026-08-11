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
