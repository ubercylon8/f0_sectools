"""Parse the agent-authored narrative Markdown into structured content.

The persona agent writes a small file with fixed `##` headers. Parsing is
tolerant: unknown headers are ignored and missing sections degrade to empty.
Redaction is applied later, at the emit layer — this module only structures text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_HEADER_RE = re.compile(r"^\s*##\s+(.*?)\s*$")
_LIST_RE = re.compile(r"^\s*(?:[-*]|\d+\.)\s+(.*\S)\s*$")

_SUMMARY_KEYS = {"executive summary", "resumen ejecutivo"}
_RISK_KEYS = {"risk framing", "top risks", "riesgos", "marco de riesgo"}
_QUESTION_KEYS = {"open questions", "preguntas abiertas"}


@dataclass(frozen=True)
class Narrative:
    executive_summary: str = ""
    risk_framing: str = ""
    open_questions: list[str] = field(default_factory=list)


def _split_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        m = _HEADER_RE.match(line)
        if m:
            current = m.group(1).strip().lower()
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return sections


def _body(sections: dict[str, list[str]], keys: set[str]) -> list[str]:
    for header, lines in sections.items():
        if header in keys:
            return lines
    return []


def _to_prose(lines: list[str]) -> str:
    return "\n".join(lines).strip()


def _to_questions(lines: list[str]) -> list[str]:
    items = [m.group(1).strip() for line in lines if (m := _LIST_RE.match(line))]
    if items:
        return items
    return [ln.strip() for ln in lines if ln.strip()]


def parse_narrative(text: str) -> Narrative:
    sections = _split_sections(text)
    return Narrative(
        executive_summary=_to_prose(_body(sections, _SUMMARY_KEYS)),
        risk_framing=_to_prose(_body(sections, _RISK_KEYS)),
        open_questions=_to_questions(_body(sections, _QUESTION_KEYS)),
    )
