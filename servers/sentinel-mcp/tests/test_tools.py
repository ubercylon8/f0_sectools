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


async def test_probe_returns_table_names(fake):
    client = fake(rows={USAGE: _TABLES})
    assert await probe.probed_tables(client) == {
        "CommonSecurityLog", "Cisco_Umbrella_dns_CL", "OfficeActivity", "SecurityIncident",
    }


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
    client = fake(rows={USAGE: _TABLES})
    out = await tools.list_data_sources(client)
    ev = {e.key: e.value for f in out for e in f.evidence}
    assert ev.get("family") in {"firewall", "dns_web", "office", "incident", "custom", "identity"}


async def test_list_data_sources_maps_403_to_posture(fake):
    client = fake(raise_on={USAGE: GraphError(403, "forbidden")})
    out = await tools.list_data_sources(client)
    assert len(out) == 1 and out[0].finding_type.value == "posture"
