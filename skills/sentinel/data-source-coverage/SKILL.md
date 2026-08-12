---
name: data-source-coverage
description: Audit what telemetry Sentinel ingests and what is missing
version: 1.0.0
metadata:
  hermes:
    tags: [security, sentinel, siem, coverage, posture]
    category: security
---

# Sentinel Data-Source Coverage

## When to Use

When asked "what are we collecting?", "is our SIEM seeing the firewall?",
"where are our visibility gaps?", or before any Sentinel hunt when you do not
yet know which tables exist. Every workspace ingests a different set — never
assume a table is present.

## Procedure

Base tool names: `list_data_sources`, `get_detection_coverage`.

1. Call `list_data_sources`. It returns each table ingesting in the last 30
   days with a family label and a `gb_30d` volume figure.
2. Group by family and state coverage plainly: which of firewall, dns_web,
   office, identity and incident are present, and which are absent. Anything
   that does not match those five prefixes is grouped under `custom` — do not
   silently drop it from the summary.
3. Use `gb_30d` to judge whether a present feed is healthy or a trickle. A
   table can be "ingesting" and still be near-useless for hunting if its
   volume is a rounding error next to the rest of the workspace — say so
   rather than treating presence as sufficiency.
4. Call `get_detection_coverage` to add the detection side — ingesting data
   with no analytics rules is collection, not detection.
5. Report gaps as gaps. A missing family is a finding, not an omission.

## Pitfalls

- **A table ingesting is not a table that is useful.** Check `gb_30d` and
  whether the fields you need are populated before promising an answer from
  it — see the network-investigation skill for a concrete example (the
  firewall table has almost no URL data despite ingesting fine).
- **Do not use the connector list as a coverage answer.** AMA/DCR and codeless
  connectors do not register there; `list_data_sources` reads actual ingest.
- **Absence is a real answer, and it is a different answer from "nothing
  found".** If `list_data_sources` has no row for a table (or a hunt tool
  returns a posture finding saying so), say the workspace has no feed for
  that surface — do not report "no malicious traffic found", which claims the
  telemetry was checked and came back clean.

## Verification

Coverage claims must trace to a `list_data_sources` row. If you cannot name the
table, do not claim the visibility.
