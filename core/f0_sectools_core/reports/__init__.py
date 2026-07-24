"""Deterministic, platform-free report engine.

Turns an intermediate ReportContent model into Markdown and HTML; WeasyPrint
renders the HTML to PDF. This package is model-free and platform-free — it never
imports a servers/* package or a platform SDK (core is imported BY servers, not
the reverse). All platform wiring lives in scripts/gen_report.py.
"""
from __future__ import annotations

from .content import (
    BlockKind,
    MetricCard,
    ReportContent,
    ReportOutput,
    ScopeMeta,
    Section,
)

__all__ = [
    "BlockKind",
    "MetricCard",
    "Section",
    "ScopeMeta",
    "ReportContent",
    "ReportOutput",
]
