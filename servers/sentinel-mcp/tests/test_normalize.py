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
