"""Per-persona section maps and finding grouping.

Defines which sections a persona report contains, in order, at which tier, and
which finding bucket feeds each data section. `is_not_assessed` centralizes the
"dark platform" test so the builder and the gather layer agree on it.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from f0_sectools_core.schema.findings import Finding, FindingType, Severity

from .content import BlockKind


class FindingGroup(StrEnum):
    posture = "posture"
    top_risks = "top_risks"
    detections = "detections"
    telemetry = "telemetry"
    exposure = "exposure"
    identity = "identity"
    compliance = "compliance"
    all = "all"


@dataclass(frozen=True)
class SectionSpec:
    kind: BlockKind
    title_key: str
    tier: str
    group: FindingGroup | None = None


TIER: dict[str, str] = {
    "ciso": "executive",
    "detection_engineer": "operational",
    "threat_hunter": "operational",
    "security_engineer": "operational",
}

# Title substrings emitted by Finding.permission_missing / rate_limited /
# api_unavailable. Coupled to those factory titles by design (documented so a
# change there updates this list). All are lowercase-compared.
DEGRADATION_MARKERS: tuple[str, ...] = (
    "not granted",
    "not licensed",
    "not configured",
    "temporarily unavailable",
    "rate limited",
)

_EXEC = "executive"
_OPS = "operational"

SECTION_MAPS: dict[str, list[SectionSpec]] = {
    "ciso": [
        SectionSpec(BlockKind.narrative, "sec_executive_summary", _EXEC),
        SectionSpec(BlockKind.metric_grid, "sec_posture", _EXEC, FindingGroup.posture),
        SectionSpec(BlockKind.finding_rollup, "sec_top_risks", _EXEC, FindingGroup.top_risks),
        SectionSpec(BlockKind.coverage, "sec_scope", _EXEC),
        SectionSpec(BlockKind.open_questions, "sec_open_questions", _EXEC),
        SectionSpec(BlockKind.provenance, "sec_provenance", _EXEC),
    ],
    "detection_engineer": [
        SectionSpec(BlockKind.narrative, "sec_executive_summary", _OPS),
        SectionSpec(BlockKind.finding_table, "sec_findings", _OPS, FindingGroup.detections),
        SectionSpec(BlockKind.coverage, "sec_scope", _OPS),
        SectionSpec(BlockKind.open_questions, "sec_open_questions", _OPS),
        SectionSpec(BlockKind.provenance, "sec_provenance", _OPS),
    ],
    "threat_hunter": [
        SectionSpec(BlockKind.narrative, "sec_executive_summary", _OPS),
        SectionSpec(BlockKind.finding_table, "sec_findings", _OPS, FindingGroup.telemetry),
        SectionSpec(BlockKind.coverage, "sec_scope", _OPS),
        SectionSpec(BlockKind.open_questions, "sec_open_questions", _OPS),
        SectionSpec(BlockKind.provenance, "sec_provenance", _OPS),
    ],
    "security_engineer": [
        SectionSpec(BlockKind.narrative, "sec_executive_summary", _OPS),
        SectionSpec(BlockKind.finding_table, "sec_findings", _OPS, FindingGroup.all),
        SectionSpec(BlockKind.coverage, "sec_scope", _OPS),
        SectionSpec(BlockKind.open_questions, "sec_open_questions", _OPS),
        SectionSpec(BlockKind.provenance, "sec_provenance", _OPS),
    ],
}


def is_not_assessed(f: Finding) -> bool:
    """True when a finding is a dark-platform degradation (render as 'not assessed')."""
    if f.finding_type is not FindingType.posture or f.severity is not Severity.info:
        return False
    title = f.title.lower()
    return any(marker in title for marker in DEGRADATION_MARKERS)


def group_findings(findings: list[Finding], persona: str) -> dict[FindingGroup, list[Finding]]:
    """Bucket findings for a persona's data sections.

    v1 keeps this simple: every real (non-degradation) finding lands in the
    `all`, `top_risks`, and the persona's primary operational group so a
    section always has something to render. Degradation findings are excluded
    from data buckets (they surface only in the coverage section).
    """
    real = [f for f in findings if not is_not_assessed(f)]
    buckets: dict[FindingGroup, list[Finding]] = {g: [] for g in FindingGroup}
    buckets[FindingGroup.all] = list(real)
    buckets[FindingGroup.top_risks] = list(real)
    buckets[FindingGroup.posture] = [f for f in findings if f.finding_type is FindingType.posture]
    for f in real:
        if f.source == "tenable":
            buckets[FindingGroup.exposure].append(f)
        elif f.source == "entra":
            buckets[FindingGroup.identity].append(f)
        elif f.source == "intune":
            buckets[FindingGroup.compliance].append(f)
        elif f.source == "limacharlie":
            buckets[FindingGroup.telemetry].append(f)
            buckets[FindingGroup.detections].append(f)
        elif f.source == "defender":
            buckets[FindingGroup.detections].append(f)
    return buckets
