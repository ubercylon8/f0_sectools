"""Collapse three vendors' inconsistent fields into one small-model vocabulary.

This module is the server's actual product. Raw `DeviceAction` on the CEF table
carries 15+ mixed-case, mixed-semantic values (Accept, blocked, Drop, Detect,
detected, Bypass, "Failed Log In", crash, RADIUS-auth-failure, negotiate,
DHCP-no-response, ...), and the three Cisco Umbrella tables express the same
allow/block concept under three different field NAMES in three different
CASINGS (Action_s=Allowed/Blocked, Verdict_s=ALLOWED/BLOCKED,
verdict_s=ALLOW/BLOCK). Exposing any of that to a small model is the
"40-value enum the model picks wrong from" failure CLAUDE.md names explicitly.

Everything here is table-driven so a new vendor is a SURFACE_SPECS entry, not a
tool rewrite. Field names, action values, and junk values -- including the
`vpn` surface's -- were verified against live data 2026-08-11.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

ACTIONS = ("allowed", "blocked", "detected", "any")
SURFACES = ("dns", "web", "vpn")
WORKLOADS = ("sharepoint", "onedrive", "exchange", "teams", "any")

DEFAULT_HOURS = 24.0

# Strict charsets for anything spliced into KQL. httpx does not escape a query
# body, so these are the injection boundary as well as small-model guidance.
# Matched with .fullmatch() everywhere, not .match(): a bare `$` anchor matches
# just before a trailing "\n" even without re.MULTILINE, so a `.match()` call
# would let a trailing newline ride along into a spliced KQL literal.
IP_RE = re.compile(r"^[0-9a-fA-F:.]{1,45}$")
PORT_RE = re.compile(r"^\d{1,5}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9._*-]{1,253}$")
WORD_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
UPN_RE = re.compile(r"^[A-Za-z0-9@._-]{1,128}$")


@dataclass(frozen=True)
class Surface:
    """One queryable telemetry surface: its table, action vocabulary, and filters."""

    table: str
    action_field: str
    action_map: dict[str, tuple[str, ...]]
    indicator_fields: tuple[str, ...]
    project: tuple[str, ...]
    indicator_kind: str = "domain"
    # Numeric-typed field (if any) matched with `==` instead of `has`. Kusto's
    # `has` requires a string operand; an int-typed column like DestinationPort
    # must never appear in indicator_fields' `has` fallback.
    port_field: str | None = None
    junk: tuple[str, ...] = field(default_factory=tuple)


SURFACE_SPECS: dict[str, Surface] = {
    # Check Point VPN-1/FireWall-1 dominates this table; Fortinet FortiGate also
    # lands here. Live fill rates (824K rows/1h): SourceIP 99.8%, DestinationIP
    # 98.7%, DestinationPort 96.6% -- but RequestURL 0.08%, SourceUserName 0.28%,
    # DestinationHostName 0.57%. Hence indicator_kind="net": IP/port only.
    "firewall": Surface(
        table="CommonSecurityLog",
        action_field="DeviceAction",
        action_map={
            "allowed": ("Accept", "Bypass"),
            "blocked": ("Drop", "blocked", "Reject"),
            "detected": ("Detect", "detected"),
        },
        # DestinationPort is int-typed in CommonSecurityLog -- excluded from
        # indicator_fields (Kusto `has` requires a string operand) and matched
        # separately via port_field's `==` equality.
        indicator_fields=("SourceIP", "DestinationIP"),
        project=(
            "TimeGenerated", "DeviceVendor", "DeviceProduct", "DeviceAction",
            "SourceIP", "DestinationIP", "DestinationPort", "Activity",
        ),
        indicator_kind="net",
        port_field="DestinationPort",
    ),
    "dns": Surface(
        table="Cisco_Umbrella_dns_CL",
        action_field="Action_s",
        action_map={"allowed": ("Allowed",), "blocked": ("Blocked",)},
        # Live fill rates (2026-08-12, 24h): Identities_s 100% / 1,245 distinct,
        # identity types "AD Users" + "Anyconnect Roaming Client". The "who"
        # behind a DNS query is in the row; these fields make it searchable, so
        # "which host resolved X" and "what did host Y resolve" are one call
        # each instead of a correlation hunt across other platforms.
        indicator_fields=("Domain_s", "InternalIp_s", "ExternalIp_s", "Identities_s"),
        project=(
            "TimeGenerated", "Action_s", "Domain_s", "Categories_s",
            "InternalIp_s", "ExternalIp_s", "Identities_s", "QueryType_s",
        ),
        junk=("Action",),
    ),
    "web": Surface(
        table="Cisco_Umbrella_proxy_CL",
        action_field="Verdict_s",
        action_map={"allowed": ("ALLOWED",), "blocked": ("BLOCKED",)},
        # Identities_s 100% / 1,114 distinct; Host_Name_s 100% (24h sample).
        indicator_fields=("URL_s", "Destination_IP_s", "Internal_IP_s", "Identities_s"),
        project=(
            "TimeGenerated", "Verdict_s", "URL_s", "Categories_s",
            "Internal_IP_s", "Identities_s", "File_Name_s", "SHA_SHA256_s",
        ),
        junk=("Action",),
    ),
    "vpn": Surface(
        table="Cisco_Umbrella_ravpnlogs_CL",
        action_field="Event_Type_s",
        # Live-verified 2026-08-11 (7d sample): Connected=10742, Failed=1,
        # plus Disconnected=240 (a session end, not an accept/deny outcome --
        # deliberately left out of both buckets rather than guessed into one).
        action_map={"allowed": ("Connected",), "blocked": ("Failed",)},
        # Device_ID_s is 100% populated (281 distinct, matching User_ID_s).
        indicator_fields=("User_ID_s", "Public_IP_s", "Assigned_IP_s", "Device_ID_s"),
        project=(
            "TimeGenerated", "Event_Type_s", "User_ID_s", "Public_IP_s",
            "Assigned_IP_s", "VPN_Profile_s", "OS_Version_s", "Failed_Reasons_s",
        ),
        # Live-verified 2026-08-11: Event_Type_s == "Event Type" (~762/7d) is
        # the CSV header row ingested as data, same defect as dns/web.
        junk=("Event Type",),
    ),
}


def clamp_hours(hours: object, retention_days: int) -> float:
    """Bound a lookback to [1, retention_days * 24].

    Beyond retention a query returns nothing, which a model reads as "no
    activity" — a confidently wrong answer. Clamping converts that into an
    honest, in-range one.
    """
    try:
        h = float(hours)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return DEFAULT_HOURS
    if h < 1:
        return 1.0
    return min(h, float(retention_days * 24))


def timespan(hours: float) -> str:
    """ISO-8601 duration for the query API's `timespan` parameter."""
    return f"PT{hours:g}H"


def _kql_list(values: tuple[str, ...]) -> str:
    return ", ".join(f'"{v}"' for v in values)


def action_clause(spec: Surface, action: str) -> str:
    """`| where <field> in~ (...)` for a semantic action, or "" for `any`.

    `in~` is case-insensitive, which is what absorbs ALLOW vs ALLOWED vs Allowed
    without a per-vendor casing table.
    """
    values = spec.action_map.get(action)
    if not values:
        return ""
    return f"| where {spec.action_field} in~ ({_kql_list(values)})"


def hygiene_clause(spec: Surface) -> str:
    """Drop CSV header rows that the connector ingested as data.

    Verified 2026-08-11: Action_s == "Action" (~2.3K rows/day),
    Verdict_s == "Action" (~1.2K/day), Event_Type_s == "Event Type"
    (~762 rows/7d). Without this every "top values" answer carries a
    phantom bucket.
    """
    if not spec.junk:
        return ""
    return f"| where {spec.action_field} !in~ ({_kql_list(spec.junk)})"


def validate_indicator(indicator: str, kind: str) -> bool:
    """True if the indicator is safe to splice into KQL AND meaningful for `kind`.

    An empty indicator always returns True regardless of `kind`: empty means
    "no indicator filter requested," which is valid for every `kind` -- it is
    not a claim that an empty string is itself a meaningful match. Callers that
    build a query must treat empty as a no-op themselves (indicator_clause does).
    """
    if not indicator:
        return True
    if kind == "net":
        return bool(IP_RE.fullmatch(indicator) or PORT_RE.fullmatch(indicator))
    # UPN_RE widens the charset by exactly one character, "@", so an Umbrella
    # identity (an AD user) is a usable indicator. It stays inside the same
    # injection boundary as DOMAIN_RE -- no quote, backslash or whitespace.
    return bool(DOMAIN_RE.fullmatch(indicator) or UPN_RE.fullmatch(indicator))


def indicator_clause(spec: Surface, indicator: str) -> str:
    """`| where <f1> has "x" or <f2> has "x" ...` across the surface's fields.

    A numeric port match (spec.port_field) always uses `==` equality instead,
    since Kusto's `has` requires a string operand and never belongs in
    indicator_fields. Callers MUST have run validate_indicator first; this
    function assumes a charset with no quotes or backslashes.
    """
    if not indicator:
        return ""
    if spec.port_field and PORT_RE.fullmatch(indicator):
        return f'| where {spec.port_field} == {int(indicator)}'
    terms = " or ".join(f'{f} has "{indicator}"' for f in spec.indicator_fields)
    return f"| where {terms}"
