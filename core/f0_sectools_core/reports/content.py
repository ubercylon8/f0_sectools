"""Intermediate representation for a report.

One model, two emitters (emit.to_markdown / emit.to_html) that stay structurally
in step. Finding rows are report-owned and tier-aware: executive tier renders
compact one-liners with no evidence/MITRE, operational tier renders dense rows
(source · ATT&CK ids + all evidence pairs) — Markdown and HTML share the same
tier logic, so the two formats stay in step. A Section carries exactly one
payload shape, selected by its kind.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from f0_sectools_core.schema.findings import Finding


class BlockKind(StrEnum):
    narrative = "narrative"          # model prose (redacted at emit)
    metric_grid = "metric_grid"      # executive big-number cards
    finding_rollup = "finding_rollup"  # CISO top-risks, compact executive-tier rows
    finding_table = "finding_table"  # operational dense finding rows
    coverage = "coverage"            # assessed / not-assessed lines
    open_questions = "open_questions"  # numbered questions for the operator
    provenance = "provenance"        # generation stamp


@dataclass(frozen=True)
class MetricCard:
    label: str   # i18n'd pillar label, e.g. "Config hardening"
    value: str   # "62%", "3", or the not-assessed label
    state: str   # one-word machine state: strong | needs-work | exposure | not-assessed


@dataclass(frozen=True)
class Section:
    kind: BlockKind
    title: str
    tier: str    # "executive" | "operational"
    text: str = ""
    items: list[str] = field(default_factory=list)
    metrics: list[MetricCard] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass(frozen=True)
class ScopeMeta:
    generated_at: str            # injected by the CLI (deterministic for tests)
    tenant_label: str
    window_label: str
    platforms_queried: list[str]
    findings_count: int
    assessed: list[str]
    not_assessed: list[str]
    pillar_metrics: list[MetricCard] = field(default_factory=list)


@dataclass(frozen=True)
class ReportContent:
    persona: str
    language: str
    tier: str
    title: str
    subtitle: str
    sections: list[Section]


@dataclass(frozen=True)
class ReportOutput:
    markdown: str
    html: str
