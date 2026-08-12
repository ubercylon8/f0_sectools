"""Contract tests for the vendor normalization layer.

The action vocabulary is the small-model contract: raw DeviceAction has 15+
mixed-case values (Accept/blocked/Drop/Detect/detected/Bypass/crash/...), which
is exactly the oversized enum CLAUDE.md forbids exposing.
"""
from __future__ import annotations

from f0_sentinel_mcp import normalize as n


def test_clamp_hours_bounds_to_retention():
    assert n.clamp_hours(24, 30) == 24.0
    assert n.clamp_hours(10_000, 30) == 720.0      # 30d retention
    assert n.clamp_hours(10_000, 90) == 2160.0     # honours a longer retention
    assert n.clamp_hours(0, 30) == 1.0
    assert n.clamp_hours(-5, 30) == 1.0
    assert n.clamp_hours("banana", 30) == 24.0     # unparseable -> default


def test_timespan_is_iso8601_duration():
    assert n.timespan(24) == "PT24H"
    assert n.timespan(0.5) == "PT0.5H"


def test_action_clause_maps_semantics_to_messy_vendor_values():
    fw = n.SURFACE_SPECS["firewall"]
    blocked = n.action_clause(fw, "blocked")
    # Case-insensitive `in~` is what absorbs Drop vs blocked vs BLOCK.
    assert "in~" in blocked
    assert "Drop" in blocked and "blocked" in blocked
    assert "Accept" not in blocked


def test_action_clause_any_emits_no_filter():
    assert n.action_clause(n.SURFACE_SPECS["firewall"], "any") == ""


def test_every_surface_supports_allowed_and_blocked():
    for name, spec in n.SURFACE_SPECS.items():
        assert "allowed" in spec.action_map, name
        assert "blocked" in spec.action_map, name


def test_umbrella_surfaces_use_three_different_field_names():
    # Verified live 2026-08-11: the same concept is Action_s / Verdict_s /
    # verdict_s across three tables. This test pins that so a refactor that
    # "tidies" them into one name fails loudly.
    assert n.SURFACE_SPECS["dns"].action_field == "Action_s"
    assert n.SURFACE_SPECS["web"].action_field == "Verdict_s"
    assert n.SURFACE_SPECS["vpn"].action_field == "Event_Type_s"


def test_hygiene_clause_filters_ingested_csv_header_rows():
    # The tenant's Umbrella connectors ingest their header row as data.
    clause = n.hygiene_clause(n.SURFACE_SPECS["dns"])
    assert "Action" in clause and "!in~" in clause


def test_hygiene_clause_empty_when_surface_has_no_junk():
    assert n.hygiene_clause(n.SURFACE_SPECS["firewall"]) == ""


def test_vpn_surface_has_a_junk_filter_for_the_csv_header_row():
    # Live-verified 2026-08-11: Event_Type_s == "Event Type" (~762 rows/7d)
    # is the CSV header ingested as data, the same defect dns/web already
    # filter. The vpn surface previously had no `junk` tuple at all.
    clause = n.hygiene_clause(n.SURFACE_SPECS["vpn"])
    assert '"Event Type"' in clause and "!in~" in clause


def test_vpn_action_map_uses_live_verified_capitalised_values():
    # Real Event_Type_s values are "Connected"/"Failed" (capitalised), plus
    # "Disconnected" which maps to neither -- it's a session end, not an
    # accept/deny outcome. The old lowercase guess only matched via `in~`'s
    # case-insensitivity, not because it was correct.
    vpn = n.SURFACE_SPECS["vpn"]
    assert vpn.action_map["allowed"] == ("Connected",)
    assert vpn.action_map["blocked"] == ("Failed",)
    mapped_values = {v for values in vpn.action_map.values() for v in values}
    assert "Disconnected" not in mapped_values


def test_validate_indicator_net_accepts_ip_and_port_rejects_domain():
    assert n.validate_indicator("10.1.2.3", "net") is True
    assert n.validate_indicator("443", "net") is True
    assert n.validate_indicator("fe80::1", "net") is True
    # The firewall table has a 0.08% RequestURL fill rate — a domain here would
    # silently return nothing, so it is rejected loudly instead.
    assert n.validate_indicator("evil.com", "net") is False


def test_validate_indicator_domain_accepts_host_rejects_injection():
    assert n.validate_indicator("evil.com", "domain") is True
    assert n.validate_indicator("*.evil.com", "domain") is True
    assert n.validate_indicator('a" or 1==1 //', "domain") is False
    assert n.validate_indicator("a\\\" | project *", "domain") is False


def test_indicator_clause_quotes_and_targets_surface_fields():
    dns = n.SURFACE_SPECS["dns"]
    clause = n.indicator_clause(dns, "evil.com")
    assert "Domain_s" in clause
    assert '"evil.com"' in clause


def test_indicator_clause_empty_indicator_yields_no_filter():
    assert n.indicator_clause(n.SURFACE_SPECS["dns"], "") == ""


def test_indicator_clause_firewall_ip_excludes_int_typed_port_field():
    # DestinationPort is int-typed in CommonSecurityLog; Kusto's `has` requires
    # a string operand, so an IP indicator must never reference it via `has`.
    fw = n.SURFACE_SPECS["firewall"]
    clause = n.indicator_clause(fw, "10.1.2.3")
    assert "DestinationPort" not in clause
    assert "SourceIP" in clause and "DestinationIP" in clause


def test_indicator_clause_firewall_port_still_uses_equality():
    fw = n.SURFACE_SPECS["firewall"]
    clause = n.indicator_clause(fw, "443")
    assert clause == "| where DestinationPort == 443"


def test_validate_indicator_empty_string_passes_for_every_kind():
    # Empty means "no indicator filter requested," not "matches nothing" — it
    # is valid for every kind. indicator_clause independently treats empty as
    # a no-op; this pins the flag's own contract so that coupling isn't left
    # implicit.
    assert n.validate_indicator("", "net") is True
    assert n.validate_indicator("", "domain") is True


# --- Identity/IP search on the Umbrella surfaces -------------------------
# Live-verified 2026-08-12 on the validation workspace: Identities_s is 100%
# populated on Cisco_Umbrella_dns_CL (1,245 distinct in 24h; identity types are
# "AD Users" and "Anyconnect Roaming Client"), and `has` matched a token drawn
# from the same row on 359,304 of 359,304 rows. The "who" was always in the row
# the tool already returned -- it just could not be searched for.

def test_dns_indicator_searches_the_ip_columns():
    """`_INDICATOR_HELP` promised IP matching for dns; only Domain_s was searched."""
    spec = n.SURFACE_SPECS["dns"]
    clause = n.indicator_clause(spec, "192.168.1.29")
    assert "InternalIp_s has" in clause
    assert "ExternalIp_s has" in clause


def test_dns_indicator_searches_identity():
    clause = n.indicator_clause(n.SURFACE_SPECS["dns"], "lt-tpl-l114")
    assert "Identities_s has" in clause


def test_web_indicator_searches_identity():
    clause = n.indicator_clause(n.SURFACE_SPECS["web"], "lt-tpl-l114")
    assert "Identities_s has" in clause


def test_a_upn_is_a_valid_indicator():
    """Umbrella identities are AD users, so an indicator must survive an '@'."""
    assert n.validate_indicator("rherrera@example.gob.do", "domain") is True


def test_upn_widening_still_rejects_a_kql_break_out():
    """The charset is the injection boundary; widening it must not open a quote."""
    for bad in ['a" or 1==1 //', "a\\b", "a'b", "a b"]:
        assert n.validate_indicator(bad, "domain") is False


def test_identity_is_projected_on_the_umbrella_surfaces():
    """Returning the answer matters as much as being able to search for it."""
    for surface in ("dns", "web"):
        assert "Identities_s" in n.SURFACE_SPECS[surface].project


# --- Umbrella cloud firewall (CDFW) -------------------------------------
# Live-verified 2026-08-12 (24h, 3,630,796 rows): Identity_s 100% populated /
# 286 distinct, Identity_Type_s "AD Users" on 3,629,629 rows; SourceIP,
# destinationIp_s, destinationPort_s and Bytes_Sent_s all 100%. By contrast
# CommonSecurityLog carries SourceUserName on 0.14% of 108M rows/7d — the two
# firewalls are complements, not duplicates: the perimeter sees the traffic,
# the cloud sees who made it.

def test_cloud_firewall_surface_targets_the_umbrella_table():
    assert n.SURFACE_SPECS["cloud_firewall"].table == "Cisco_Umbrella_firewall_CL"


def test_firewall_surface_names_map_to_specs():
    assert n.FIREWALL_SURFACES["perimeter"] == "firewall"
    assert n.FIREWALL_SURFACES["cloud"] == "cloud_firewall"


def test_cloud_firewall_action_vocabulary_is_its_own():
    """Live values are ALLOW/BLOCK, not the CEF Accept/Drop/Detect."""
    spec = n.SURFACE_SPECS["cloud_firewall"]
    assert "ALLOW" in n.action_clause(spec, "allowed")
    assert "BLOCK" in n.action_clause(spec, "blocked")


def test_cloud_firewall_drops_the_ingested_csv_header_row():
    """verdict_s == "Action" is a header row ingested as data (~1,152/24h)."""
    clause = n.hygiene_clause(n.SURFACE_SPECS["cloud_firewall"])
    assert "verdict_s !in~" in clause
    assert '"Action"' in clause


def test_cloud_firewall_is_searchable_by_identity_ip_and_port():
    clause = n.indicator_clause(n.SURFACE_SPECS["cloud_firewall"], "10.1.2.3")
    for f in ("Identity_s", "SourceIP", "destinationIp_s", "destinationPort_s"):
        assert f"{f} has" in clause


def test_cloud_firewall_aggregates_by_identity():
    """Grouping by user is what this table adds over the perimeter firewall."""
    assert n.SURFACE_SPECS["cloud_firewall"].indicator_fields[0] == "Identity_s"


def test_cloud_firewall_does_not_advertise_its_empty_columns():
    """FQDNS 2.5%, Destination_Country 1%, App_ID 0.8% — searching them would
    answer "nothing found" to questions that were never really asked."""
    spec = n.SURFACE_SPECS["cloud_firewall"]
    for absent in ("FQDNS_s", "Destination_Country_s", "App_ID_s"):
        assert absent not in spec.indicator_fields


def test_a_flow_indicator_accepts_an_identity_and_a_port():
    assert n.validate_indicator("someone@example.gob.do", "flow") is True
    assert n.validate_indicator("443", "flow") is True
    assert n.validate_indicator('x" or 1==1', "flow") is False
