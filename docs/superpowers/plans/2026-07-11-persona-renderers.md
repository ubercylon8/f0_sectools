# Persona Renderers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the planned-only `core/renderers/` — a deterministic library that turns a `Finding` (or list) into audience-shaped Markdown text for five personas.

**Architecture:** A template-method base class (`Renderer`) implements the public `render_finding`/`render_findings` methods and shared formatting helpers; five persona subclasses override two hooks (`_finding_body`, `_aggregate`). Every rendered string passes through the existing `redact_text` before return. No schema change, no new dependency.

**Tech Stack:** Python 3.11+ (`StrEnum`), Pydantic `Finding` model (existing), `pytest`. Only internal imports: `f0_sectools_core.schema.findings` and `f0_sectools_core.redaction.redact`.

## Global Constraints

- Findings schema (`core/f0_sectools_core/schema/findings.py`) is the source of truth and MUST NOT change.
- Redaction is centralized in `core/redaction` and reused, never reimplemented; every rendered string ends with `redact_text(...)`.
- Five personas, values matching the agent-persona modes 1:1: `soc_analyst`, `security_engineer`, `ciso`, `threat_hunter`, `detection_engineer`. Default persona is `soc_analyst`.
- Output is Markdown text. No HTML, no ANSI colour, no templating engine.
- Deterministic: same input → byte-identical output. No clocks, no randomness; ties break on a stable key.
- Robustness: never raise on a sparse finding (`entity=None`, empty `evidence`, no `recommended_action`, no `mitre` reference) or an empty list. No rendered output contains the literal string `"None"`.
- Enum fields are read via `.value` (e.g. `f.severity.value`) for unambiguous formatting.
- The redaction marker is `REDACTED = "«redacted»"` (from `f0_sectools_core.redaction.patterns`).
- All existing tests keep passing; `ruff check .` stays clean.

---

### Task 1: `base.py` — `Persona` enum + `Renderer` base class

**Files:**
- Create: `core/f0_sectools_core/renderers/base.py`
- Test: `core/tests/test_renderers.py`

**Interfaces:**
- Consumes: `Finding`, `Reference`, `Entity`, `Evidence`, `RecommendedAction`, `Severity`, `EntityKind`, `FindingType` from `f0_sectools_core.schema.findings`; `redact_text` from `f0_sectools_core.redaction.redact`.
- Produces:
  - `Persona(StrEnum)` with members `soc_analyst`, `security_engineer`, `ciso`, `threat_hunter`, `detection_engineer`.
  - `Renderer` class with: `__init__(self, persona: Persona | None = None)`; public `render_finding(self, finding: Finding) -> str` and `render_findings(self, findings: list[Finding]) -> str`; overridable hooks `_finding_body(self, f: Finding) -> str` and `_aggregate(self, findings: list[Finding]) -> str`; static/instance helpers `_severity_tag`, `_entity_str`, `_evidence_lines`, `_reference_str`, `_reference_lines`, `_mitre_refs`, `_sort_by_severity`, `_sort_by_time`, `_severity_counts`, `_source_counts`.
  - Module constant `_NO_FINDINGS = "No findings."`

- [ ] **Step 1: Write the failing test**

Create `core/tests/test_renderers.py`:

```python
"""Contract tests for core/renderers — deterministic Finding -> Markdown text."""
from __future__ import annotations

import pytest

from f0_sectools_core.redaction.patterns import REDACTED
from f0_sectools_core.renderers.base import Persona, Renderer
from f0_sectools_core.schema.findings import (
    Entity,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Reference,
    Severity,
)


def _rich() -> Finding:
    return Finding(
        source="defender",
        finding_type=FindingType.incident,
        severity=Severity.critical,
        title="Ransomware activity on host web-01",
        entity=Entity(kind="host", id="web-01", name="web-01.corp.local"),
        evidence=[Evidence(key="failed_logins", value="142 in 5m")],
        recommended_action=RecommendedAction(
            summary="Isolate host and reset affected credentials",
            gated_action="defender.isolate_host",
            confidence="high",
        ),
        references=[Reference(type="mitre", id="T1486", url="https://attack.mitre.org/techniques/T1486/")],
        observed_at="2026-06-28T10:00:00Z",
    )


def _sparse() -> Finding:
    return Finding(
        source="entra",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title="No risky users detected",
    )


def test_base_severity_tag_is_uppercase():
    assert Renderer()._severity_tag(_rich()) == "CRITICAL"


def test_base_entity_str_handles_none():
    assert Renderer()._entity_str(_sparse()) == "unspecified target"


def test_base_entity_str_with_name():
    assert Renderer()._entity_str(_rich()) == "host: web-01.corp.local (web-01)"


def test_base_render_finding_sparse_does_not_crash_or_show_none():
    out = Renderer().render_finding(_sparse())
    assert out
    assert "None" not in out


def test_base_render_findings_empty_list():
    assert Renderer().render_findings([]) == "No findings."


def test_base_render_finding_redacts_secrets():
    f = _sparse()
    f.evidence = [Evidence(key="note", value="token Bearer abcdef0123456789xyz leaked")]
    out = Renderer().render_finding(f)
    assert REDACTED in out
    assert "abcdef0123456789xyz" not in out


def test_base_render_is_deterministic():
    r = Renderer()
    assert r.render_findings([_rich(), _sparse()]) == r.render_findings([_rich(), _sparse()])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_renderers.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'f0_sectools_core.renderers.base'` (the package `__init__.py` exists but `base.py` does not).

- [ ] **Step 3: Write minimal implementation**

Create `core/f0_sectools_core/renderers/base.py`:

```python
"""Persona renderers: turn a Finding (or list) into audience-shaped Markdown text.

Deterministic and model-free — the same input yields the same output. Every
rendered string passes through core redaction as a defense-in-depth net before
it is returned (Critical Rule 3).
"""
from __future__ import annotations

from enum import StrEnum

from f0_sectools_core.redaction.redact import redact_text
from f0_sectools_core.schema.findings import Finding, Reference


class Persona(StrEnum):
    soc_analyst = "soc_analyst"
    security_engineer = "security_engineer"
    ciso = "ciso"
    threat_hunter = "threat_hunter"
    detection_engineer = "detection_engineer"


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_NO_FINDINGS = "No findings."


class Renderer:
    """Base renderer with generic defaults. Personas override the two hooks."""

    persona: Persona = Persona.soc_analyst

    def __init__(self, persona: Persona | None = None) -> None:
        if persona is not None:
            self.persona = persona

    # ── public template methods ──────────────────────────────────────
    def render_finding(self, finding: Finding) -> str:
        return redact_text(self._finding_body(finding))

    def render_findings(self, findings: list[Finding]) -> str:
        if not findings:
            return redact_text(_NO_FINDINGS)
        return redact_text(self._aggregate(findings))

    # ── overridable hooks (generic defaults) ─────────────────────────
    def _finding_body(self, f: Finding) -> str:
        lines = [f"**[{self._severity_tag(f)}] {f.title}**", f"Target: {self._entity_str(f)}"]
        ev = self._evidence_lines(f)
        if ev:
            lines.append("Evidence:")
            lines.extend(ev)
        if f.recommended_action is not None:
            lines.append(f"Recommended: {f.recommended_action.summary}")
        refs = self._reference_lines(f)
        if refs:
            lines.append("References: " + ", ".join(refs))
        return "\n".join(lines)

    def _aggregate(self, findings: list[Finding]) -> str:
        return "\n\n".join(self._finding_body(f) for f in self._sort_by_severity(findings))

    # ── shared helpers ───────────────────────────────────────────────
    @staticmethod
    def _severity_tag(f: Finding) -> str:
        return f.severity.value.upper()

    @staticmethod
    def _entity_str(f: Finding) -> str:
        e = f.entity
        if e is None:
            return "unspecified target"
        if e.name:
            return f"{e.kind.value}: {e.name} ({e.id})"
        return f"{e.kind.value}: {e.id}"

    @staticmethod
    def _evidence_lines(f: Finding) -> list[str]:
        return [f"- {ev.key}: {ev.value}" for ev in f.evidence]

    @staticmethod
    def _reference_str(ref: Reference) -> str:
        if ref.url:
            return f"[{ref.type}:{ref.id}]({ref.url})"
        return f"{ref.type}:{ref.id}"

    def _reference_lines(self, f: Finding) -> list[str]:
        return [self._reference_str(r) for r in f.references]

    @staticmethod
    def _mitre_refs(f: Finding) -> list[Reference]:
        return [r for r in f.references if r.type == "mitre"]

    @staticmethod
    def _sort_by_severity(findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 99))

    @staticmethod
    def _sort_by_time(findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda f: (f.observed_at is None, f.observed_at or ""))

    @staticmethod
    def _severity_counts(findings: list[Finding]) -> str:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        ordered = sorted(counts.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 99))
        return ", ".join(f"{n} {sev}" for sev, n in ordered)

    @staticmethod
    def _source_counts(findings: list[Finding]) -> str:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.source] = counts.get(f.source, 0) + 1
        return ", ".join(f"{n} {src}" for src, n in sorted(counts.items()))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest core/tests/test_renderers.py -q`
Expected: PASS (7 passed).

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/renderers/base.py core/tests/test_renderers.py
git commit -m "feat(renderers): Persona enum + Renderer base class with shared helpers"
```

---

### Task 2: `personas.py` — five persona subclasses + registry

**Files:**
- Create: `core/f0_sectools_core/renderers/personas.py`
- Test: `core/tests/test_renderers.py` (append)

**Interfaces:**
- Consumes: `Persona`, `Renderer` from `.base`; `Finding` from schema.
- Produces:
  - Classes `SocAnalystRenderer`, `SecurityEngineerRenderer`, `CisoRenderer`, `ThreatHunterRenderer`, `DetectionEngineerRenderer` (each subclasses `Renderer`, sets `persona`, overrides `_finding_body` and `_aggregate`).
  - `REGISTRY: dict[Persona, Renderer]` mapping each `Persona` member to one renderer instance.
  - `get_renderer(persona: Persona | str) -> Renderer` — coerces a `str`, raises `ValueError` on an unknown value.

- [ ] **Step 1: Write the failing test**

Append to `core/tests/test_renderers.py`:

```python
from f0_sectools_core.renderers.personas import REGISTRY, get_renderer


def _mixed() -> list[Finding]:
    return [
        Finding(
            source="defender", finding_type=FindingType.incident, severity=Severity.high,
            title="Suspicious PowerShell", entity=Entity(kind="host", id="pc-9"),
            references=[Reference(type="mitre", id="T1059")],
            observed_at="2026-06-28T12:00:00Z",
        ),
        Finding(
            source="entra", finding_type=FindingType.risk, severity=Severity.critical,
            title="Impossible travel sign-in", entity=Entity(kind="user", id="alice"),
            evidence=[Evidence(key="geo", value="US then RU in 4m")],
            observed_at="2026-06-28T09:00:00Z",  # earlier than the defender one
        ),
        Finding(
            source="limacharlie", finding_type=FindingType.misconfig, severity=Severity.medium,
            title="EDR sensor offline",
            recommended_action=RecommendedAction(summary="Reinstall the sensor on host db-2"),
        ),
    ]


def test_registry_has_all_five_personas():
    assert set(REGISTRY) == set(Persona)


def test_get_renderer_coerces_str():
    assert get_renderer("ciso") is REGISTRY[Persona.ciso]


def test_get_renderer_unknown_raises_valueerror():
    with pytest.raises(ValueError, match="Unknown persona"):
        get_renderer("cto")


def test_ciso_list_has_counts_and_omits_raw_evidence():
    out = get_renderer(Persona.ciso).render_findings(_mixed())
    assert "1 critical" in out
    assert "US then RU in 4m" not in out  # CISO never dumps raw evidence


def test_threat_hunter_list_is_timeline_ordered():
    out = get_renderer(Persona.threat_hunter).render_findings(_mixed())
    # the 09:00 sign-in must appear before the 12:00 PowerShell finding
    assert out.index("2026-06-28T09:00:00Z") < out.index("2026-06-28T12:00:00Z")


def test_detection_engineer_flags_unmapped_and_shows_technique():
    out = get_renderer(Persona.detection_engineer).render_findings(_mixed())
    assert "unmapped" in out          # the entra + limacharlie findings have no mitre ref
    assert "T1059" in out             # the defender finding is mapped


def test_soc_analyst_single_shows_next_step_and_gated_action():
    out = get_renderer(Persona.soc_analyst).render_finding(_rich())
    assert "Next step:" in out
    assert "defender.isolate_host" in out


def test_security_engineer_list_is_a_checklist():
    out = get_renderer(Persona.security_engineer).render_findings(_mixed())
    assert "- [ ]" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_renderers.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'f0_sectools_core.renderers.personas'`.

- [ ] **Step 3: Write minimal implementation**

Create `core/f0_sectools_core/renderers/personas.py`:

```python
"""The five concrete persona renderers plus the registry and lookup."""
from __future__ import annotations

from f0_sectools_core.schema.findings import Finding

from .base import Persona, Renderer


class SocAnalystRenderer(Renderer):
    """Tactical, per-incident: what happened + the next triage step."""

    persona = Persona.soc_analyst

    def _finding_body(self, f: Finding) -> str:
        lines = [f"**[{self._severity_tag(f)}] {f.title}**", f"Target: {self._entity_str(f)}"]
        ev = self._evidence_lines(f)
        if ev:
            lines.append("What happened:")
            lines.extend(ev)
        if f.recommended_action is not None:
            step = f"Next step: {f.recommended_action.summary}"
            if f.recommended_action.gated_action:
                step += f" (gated action: {f.recommended_action.gated_action})"
            lines.append(step)
        return "\n".join(lines)

    def _aggregate(self, findings: list[Finding]) -> str:
        ordered = self._sort_by_severity(findings)
        header = f"{len(ordered)} findings ({self._severity_counts(ordered)})"
        return header + "\n\n" + "\n\n".join(self._finding_body(f) for f in ordered)


class SecurityEngineerRenderer(Renderer):
    """Config & hardening: a remediation checklist grouped by platform."""

    persona = Persona.security_engineer

    def _finding_body(self, f: Finding) -> str:
        fix = f.recommended_action.summary if f.recommended_action else f.title
        return f"- [ ] {fix} ({f.source}/{f.finding_type.value})"

    def _aggregate(self, findings: list[Finding]) -> str:
        groups: dict[str, list[Finding]] = {}
        for f in self._sort_by_severity(findings):
            groups.setdefault(f.source, []).append(f)
        lines = ["## Remediation checklist"]
        for source in sorted(groups):
            lines.append(f"### {source}")
            lines.extend(self._finding_body(f) for f in groups[source])
        return "\n".join(lines)


class CisoRenderer(Renderer):
    """Aggregate, business-framed: a severity/source rollup, no raw evidence."""

    persona = Persona.ciso

    def _finding_body(self, f: Finding) -> str:
        return f"- [{self._severity_tag(f)}] {f.title} — {self._entity_str(f)}"

    def _aggregate(self, findings: list[Finding]) -> str:
        top = self._sort_by_severity(findings)[:5]
        crit_high = sum(1 for f in findings if f.severity.value in ("critical", "high"))
        lines = [
            "## Security posture rollup",
            f"Total findings: {len(findings)}",
            f"By severity: {self._severity_counts(findings)}",
            f"By source: {self._source_counts(findings)}",
            "Top findings:",
        ]
        lines.extend(self._finding_body(f) for f in top)
        lines.append(f"Risk posture: {crit_high} critical/high finding(s) require attention.")
        return "\n".join(lines)


class ThreatHunterRenderer(Renderer):
    """Timeline & pivots: chronological, entities as pivots, IOCs + ATT&CK."""

    persona = Persona.threat_hunter

    def _finding_body(self, f: Finding) -> str:
        ts = f.observed_at or "unknown time"
        lines = [f"{ts} — [{self._severity_tag(f)}] {f.title}", f"Pivot: {self._entity_str(f)}"]
        ev = self._evidence_lines(f)
        if ev:
            lines.append("IOCs:")
            lines.extend(ev)
        mitre = self._mitre_refs(f)
        if mitre:
            lines.append("ATT&CK: " + ", ".join(self._reference_str(r) for r in mitre))
        return "\n".join(lines)

    def _aggregate(self, findings: list[Finding]) -> str:
        lines = ["## Timeline"]
        lines.extend(self._finding_body(f) for f in self._sort_by_time(findings))
        return "\n".join(lines)


class DetectionEngineerRenderer(Renderer):
    """Alert quality & coverage: grouped by ATT&CK technique; unmapped flagged."""

    persona = Persona.detection_engineer

    def _finding_body(self, f: Finding) -> str:
        mitre = self._mitre_refs(f)
        tag = ", ".join(self._reference_str(r) for r in mitre) if mitre else "unmapped"
        return f"- [{tag}] {f.title} ({self._severity_tag(f)}, source: {f.source})"

    def _aggregate(self, findings: list[Finding]) -> str:
        mapped: dict[str, list[Finding]] = {}
        unmapped: list[Finding] = []
        for f in self._sort_by_severity(findings):
            refs = self._mitre_refs(f)
            if refs:
                for r in refs:
                    mapped.setdefault(r.id, []).append(f)
            else:
                unmapped.append(f)
        lines = ["## Detection coverage by technique"]
        for tech_id in sorted(mapped):
            lines.append(f"### {tech_id}")
            lines.extend(f"- {f.title} ({self._severity_tag(f)})" for f in mapped[tech_id])
        if unmapped:
            lines.append("### unmapped (no ATT&CK reference)")
            lines.extend(f"- {f.title} ({self._severity_tag(f)})" for f in unmapped)
        return "\n".join(lines)


REGISTRY: dict[Persona, Renderer] = {
    Persona.soc_analyst: SocAnalystRenderer(),
    Persona.security_engineer: SecurityEngineerRenderer(),
    Persona.ciso: CisoRenderer(),
    Persona.threat_hunter: ThreatHunterRenderer(),
    Persona.detection_engineer: DetectionEngineerRenderer(),
}


def get_renderer(persona: Persona | str) -> Renderer:
    """Return the renderer for a persona, coercing a str; ValueError if unknown."""
    try:
        key = Persona(persona)
    except ValueError as e:
        valid = ", ".join(p.value for p in Persona)
        raise ValueError(f"Unknown persona '{persona}'. Valid personas: {valid}") from e
    return REGISTRY[key]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest core/tests/test_renderers.py -q`
Expected: PASS (all Task 1 + Task 2 tests).

- [ ] **Step 5: Commit**

```bash
git add core/f0_sectools_core/renderers/personas.py core/tests/test_renderers.py
git commit -m "feat(renderers): five persona subclasses + registry + get_renderer"
```

---

### Task 3: `__init__.py` — public API

**Files:**
- Modify: `core/f0_sectools_core/renderers/__init__.py` (currently a one-line docstring placeholder)
- Test: `core/tests/test_renderers.py` (append)

**Interfaces:**
- Consumes: `Persona`, `Renderer` from `.base`; `REGISTRY`, `get_renderer` from `.personas`; `Finding` from schema.
- Produces:
  - `render_finding(finding: Finding, persona: Persona | str = Persona.soc_analyst) -> str`
  - `render_findings(findings: list[Finding], persona: Persona | str = Persona.soc_analyst) -> str`
  - Re-exports `Persona`, `Renderer`, `get_renderer` via `__all__`.

- [ ] **Step 1: Write the failing test**

Append to `core/tests/test_renderers.py`:

```python
from f0_sectools_core.renderers import render_finding, render_findings


def test_public_render_finding_default_persona_is_soc_analyst():
    # default persona shows the SOC-analyst "Next step:" framing
    assert "Next step:" in render_finding(_rich())


def test_public_render_findings_accepts_str_persona():
    out = render_findings(_mixed(), "ciso")
    assert "Security posture rollup" in out


def test_public_render_findings_unknown_persona_raises():
    with pytest.raises(ValueError, match="Unknown persona"):
        render_findings(_mixed(), "nope")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_renderers.py -q`
Expected: FAIL with `ImportError: cannot import name 'render_finding' from 'f0_sectools_core.renderers'`.

- [ ] **Step 3: Write minimal implementation**

Replace the entire contents of `core/f0_sectools_core/renderers/__init__.py`:

```python
"""Persona renderers: SOC analyst, security engineer, CISO, threat hunter, detection engineer.

Public API — a deterministic, model-free presentation layer that turns the shared
Finding schema into audience-shaped Markdown text, one shape per audience. The
structured finding is always the source of truth; this is optional polish rendered
from it, never a different data contract.
"""
from __future__ import annotations

from f0_sectools_core.schema.findings import Finding

from .base import Persona, Renderer
from .personas import REGISTRY, get_renderer

__all__ = ["Persona", "Renderer", "get_renderer", "render_finding", "render_findings", "REGISTRY"]


def render_finding(finding: Finding, persona: Persona | str = Persona.soc_analyst) -> str:
    """Render one finding as Markdown text for the given persona."""
    return get_renderer(persona).render_finding(finding)


def render_findings(findings: list[Finding], persona: Persona | str = Persona.soc_analyst) -> str:
    """Render a list of findings as Markdown text for the given persona."""
    return get_renderer(persona).render_findings(findings)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest core/tests/test_renderers.py -q`
Expected: PASS (all renderer tests).

- [ ] **Step 5: Run the full core suite + lint**

Run: `uv run pytest core/ -q && uv run ruff check core/`
Expected: all pass, ruff clean.

- [ ] **Step 6: Commit**

```bash
git add core/f0_sectools_core/renderers/__init__.py core/tests/test_renderers.py
git commit -m "feat(renderers): public render_finding/render_findings API"
```

---

### Task 4: `--persona` flag on the defender smoke script (reference consumer)

**Files:**
- Modify: `scripts/live_smoke_defender.py`

**Interfaces:**
- Consumes: `render_findings`, `Persona` from `f0_sectools_core.renderers`.
- Produces: an optional `--persona <name>` CLI flag that, when passed, additionally prints the persona-rendered view under each raw-JSON block. Default (no flag) leaves the existing raw-JSON behaviour unchanged.

**Note:** This is a mechanical edit to a script that is not exercised in CI (it needs live creds). It is verified by argparse behaviour only — `--help` and an invalid choice — which run without creds because argparse executes before `main()`.

- [ ] **Step 1: Edit the imports**

In `scripts/live_smoke_defender.py`, change the import block. Replace:

```python
import asyncio
import json

from dotenv import load_dotenv
from f0_defender_mcp import tools
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj
```

with:

```python
import argparse
import asyncio
import json

from dotenv import load_dotenv
from f0_defender_mcp import tools
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.renderers import Persona, render_findings
```

- [ ] **Step 2: Thread the persona through `_show` and `main`**

Replace the `_show` function:

```python
def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings:
        redacted = redact_obj(f.model_dump())
        print(json.dumps(redacted, indent=2, default=str))
```

with:

```python
def _show(label: str, findings, persona: str | None = None) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings:
        redacted = redact_obj(f.model_dump())
        print(json.dumps(redacted, indent=2, default=str))
    if persona is not None:
        print(f"\n--- {persona} view ---")
        print(render_findings(findings, persona))
```

Change the `main` signature. Replace:

```python
async def main() -> None:
    cfg = PlatformConfig.from_env("DEFENDER")  # raises clearly if creds missing
```

with:

```python
async def main(persona: str | None = None) -> None:
    cfg = PlatformConfig.from_env("DEFENDER")  # raises clearly if creds missing
```

- [ ] **Step 3: Pass `persona` to every `_show` call**

There are four `_show(...)` calls in `main`. Add `persona` to each:

- `_show(label, await coro)` → `_show(label, await coro, persona)`
- `_show("isolate_host INTENT (no token)", await tools.isolate_host(sec, gate_off, "smoke-device", "dry run"))` → append `, persona)` before the closing paren of `_show` (i.e. `..."dry run"), persona)`)
- `_show("isolate_host REFUSAL (flag off)", await tools.isolate_host(sec, gate_off, "smoke-device", "dry run", confirmation_token="not-a-real-token"))` → append `, persona)` after the inner call's closing paren.

The three edited call sites read:

```python
                _show(label, await coro, persona)
```
```python
        _show("isolate_host INTENT (no token)",
              await tools.isolate_host(sec, gate_off, "smoke-device", "dry run"), persona)
```
```python
        _show("isolate_host REFUSAL (flag off)",
              await tools.isolate_host(sec, gate_off, "smoke-device", "dry run",
                                       confirmation_token="not-a-real-token"), persona)  # noqa: S106 — dummy refusal token, not a credential
```

- [ ] **Step 4: Replace the `__main__` block**

Replace:

```python
if __name__ == "__main__":
    asyncio.run(main())
```

with:

```python
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live smoke test for the Defender MCP server.")
    parser.add_argument(
        "--persona",
        choices=[p.value for p in Persona],
        default=None,
        help="Also print findings rendered for this persona (raw JSON is always shown).",
    )
    args = parser.parse_args()
    asyncio.run(main(args.persona))
```

- [ ] **Step 5: Verify argparse wiring (no creds needed)**

Run: `uv run python scripts/live_smoke_defender.py --help`
Expected: usage text lists `--persona {soc_analyst,security_engineer,ciso,threat_hunter,detection_engineer}`.

Run: `uv run python scripts/live_smoke_defender.py --persona bogus`
Expected: exits non-zero (code 2) with `argument --persona: invalid choice: 'bogus'`.

- [ ] **Step 6: Lint + commit**

Run: `uv run ruff check scripts/live_smoke_defender.py`
Expected: clean.

```bash
git add scripts/live_smoke_defender.py
git commit -m "feat(renderers): optional --persona view on the defender smoke script"
```

---

### Task 5: Docs — CLAUDE.md renderer list 4→5 + core/README.md

**Files:**
- Modify: `CLAUDE.md`
- Modify: `core/README.md`

- [ ] **Step 1: Update the CLAUDE.md architecture tree**

In `CLAUDE.md`, replace:

```
    renderers/              # persona renderers (analyst/engineer/ciso/hunter)
```

with:

```
    renderers/              # persona renderers (analyst/engineer/ciso/hunter/detection-engineer)
```

- [ ] **Step 2: Add the fifth persona bullet + drop "planned"**

In `CLAUDE.md`, in the `### Persona renderers` section, replace this bullet list:

```
- **SOC analyst** — per-incident, tactical: what happened, evidence, next triage step.
- **Security engineer** — config-level: the misconfig/coverage gap and the fix.
- **CISO / risk leader** — aggregated rollups, risk scoring, exec-framed summaries.
- **Threat hunter / IR** — timeline, pivots, case-building across MISP/TheHive/OpenCTI.
```

with:

```
- **SOC analyst** — per-incident, tactical: what happened, evidence, next triage step.
- **Security engineer** — config-level: the misconfig/coverage gap and the fix.
- **CISO / risk leader** — aggregated rollups, risk scoring, exec-framed summaries.
- **Threat hunter / IR** — timeline, pivots, case-building across MISP/TheHive/OpenCTI.
- **Detection engineer** — alert quality and coverage: findings grouped by ATT&CK technique, unmapped findings flagged.
```

Then, in the same section's note, replace `` `core/renderers/` (above, planned) shapes `` with `` `core/renderers/` (above) shapes `` (the module is now built).

- [ ] **Step 3: Update core/README.md**

In `core/README.md`, replace:

```
| `renderers/`  | Persona renderers (SOC analyst, security engineer, CISO, threat hunter). |
```

with:

```
| `renderers/`  | Persona renderers (SOC analyst, security engineer, CISO, threat hunter, detection engineer). Public API: `render_finding` / `render_findings`. |
```

- [ ] **Step 4: Verify the edits landed**

Run: `grep -n "detection-engineer\|detection engineer\|Detection engineer" CLAUDE.md core/README.md`
Expected: three matches — the tree line, the new CLAUDE.md bullet, and the core/README.md row.

Run: `grep -c "above, planned" CLAUDE.md`
Expected: `0`.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md core/README.md
git commit -m "docs(renderers): document the five personas + public API (4->5)"
```

---

## Self-Review

**1. Spec coverage:**
- Module layout (`base.py`/`personas.py`/`__init__.py`) → Tasks 1–3. ✓
- Five personas matching agent modes → Task 1 (`Persona`) + Task 2 (subclasses). ✓
- `render_finding` + `render_findings`, default `soc_analyst`, str coercion, `ValueError` on unknown → Tasks 2 (`get_renderer`) + 3 (public API). ✓
- Template-method base + shared helpers → Task 1. ✓
- Per-persona shaping (analyst next-step, engineer checklist, CISO rollup no-evidence, hunter timeline, detection MITRE/unmapped) → Task 2 + its tests. ✓
- `redact_text` final pass (Rule 3) → Task 1 (`render_finding`/`render_findings`) + redaction test. ✓
- Sparse-finding robustness + empty list → Task 1 tests (`_sparse`, empty list). ✓
- Determinism → Task 1 test. ✓
- First consumer `--persona` on defender smoke, non-destructive → Task 4. ✓
- CLAUDE.md 4→5 + core/README.md → Task 5. ✓
- No schema change: no task touches `schema/findings.py`. ✓

**2. Placeholder scan:** No TBD/TODO/"handle edge cases"/"similar to". Every code step shows complete code. ✓

**3. Type consistency:** `Persona` members, `Renderer` hook names (`_finding_body`, `_aggregate`), helper names (`_severity_tag`, `_entity_str`, `_evidence_lines`, `_reference_str`, `_reference_lines`, `_mitre_refs`, `_sort_by_severity`, `_sort_by_time`, `_severity_counts`, `_source_counts`), `REGISTRY`, and `get_renderer` are used identically across Tasks 1–3 and the tests. Enum reads use `.value` consistently. `render_finding`/`render_findings` signatures match between `__init__.py` and the smoke-script call (`render_findings(findings, persona)`). ✓
