# Report Generation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate professional, persona-shaped security posture reports (Markdown + PDF, English or Spanish) from real findings — a deliverable that opens a conversation, ending with open questions for the operator.

**Architecture:** A pure, platform-free, model-free engine in `core/f0_sectools_core/reports/` turns an intermediate `ReportContent` model into Markdown and HTML (WeasyPrint renders HTML → PDF). All platform wiring — constructing the 8 clients, calling each server's `tools.py` functions to re-gather findings, and building the executive metric grid — lives in `scripts/` (respecting the rule that `core/` is imported *by* servers, never imports them). The persona agent authors the narrative (executive summary, risk framing, open questions) as a small Markdown file the builder parses; every data section is rendered deterministically from re-gathered `Finding` objects.

**Tech Stack:** Python 3.11+, Pydantic (existing findings schema), WeasyPrint (optional `[reports]` extra), `core/f0_sectools_core/renderers` (reused), `core/f0_sectools_core/redaction` (reused). Tests: pytest.

## Global Constraints

Every task's requirements implicitly include this section. Values are copied verbatim from CLAUDE.md and the design spec (`docs/superpowers/specs/2026-07-24-report-generation-design.md`).

- **`core/reports/` is platform-free and model-free.** It must NOT import any `servers/*` package, `httpx`, or any platform SDK. `core/` is imported by servers, never the reverse. All client construction and finding re-gathering lives in `scripts/`.
- **Redact everything emitted.** Every string the emitters write — narrative prose included — passes through `core.redaction.redact.redact_text` before it lands in Markdown or HTML (Critical Rule 3).
- **Grounded data sections.** Data sections render only from gathered `Finding` objects. The model's prose lands only in explicitly narrative-typed blocks. No code path lets a model-supplied number reach a data section.
- **Graceful partial.** A dark platform (missing creds/permission/licence) yields a `posture` degradation finding rendered as "not assessed"; the report still generates. Never abort because one platform is dark.
- **Local-only.** Re-gather hits only the operator's configured platforms; PDF is local (WeasyPrint). No telemetry, no external calls. Markdown always works; PDF requires the `[reports]` extra and degrades with a clear install message if absent.
- **No real tenant identifiers anywhere** — fixtures, tests, comments, docstrings, commit messages, PR bodies. Use neutral values only: tenant `Contoso`, hosts `web-01.corp.local`, users `CORP\jsmith`. The repo is public.
- **mypy strict must pass for `core/reports/`** (CI scopes mypy to `core/` + each server package; `scripts/`, `tests/`, `evals/`, `skills/` are excluded). `scripts/gen_report.py` and `scripts/report_gather.py` are therefore exempt from strict typing but must still run and be tested offline.
- **`Lang = Literal["en", "es"]`.** The persona identifier reuses the existing `core.renderers.Persona` enum values: `ciso`, `threat_hunter`, `detection_engineer`, `security_engineer` (underscores). The CLI accepts hyphenated forms (`threat-hunter`) and maps them.
- **ruff clean, findings schema unchanged.** Do not modify `core/f0_sectools_core/schema/findings.py`.
- **Regenerate generated docs + integration templates and commit** whenever a tool, tool docstring, or skill changes (`uv run python scripts/gen_docs.py`; the `test_gen_docs.py` and `test_integrations_valid.py` drift guards fail CI otherwise).
- **Commit style:** conventional commits; stage specific files (never `git add -A`). Every commit message ends with the trailers:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
  ```
  Use `git commit -F <file>` (not `-m`) when the message body contains backticks. **Do not push** — commit locally and wait for explicit instruction.

## Reference: existing interfaces this plan builds on

Read these before starting; do not restate their internals in new code.

- `core/f0_sectools_core/schema/findings.py` — `Finding` (fields: `schema_version, source, finding_type, severity, title, entity, evidence[], recommended_action, references[], observed_at`), enums `Severity`, `FindingType`, `EntityKind`, and factory classmethods `Finding.permission_missing(...)`, `Finding.rate_limited(...)`, `Finding.api_unavailable(...)` (all produce `finding_type=posture, severity=info`).
- `core/f0_sectools_core/renderers/__init__.py` — `Persona` enum, `render_findings(findings, persona) -> str`, `get_renderer(persona) -> Renderer`. Renderers already redact their output.
- `core/f0_sectools_core/redaction/redact.py` — `redact_text(str) -> str`, `redact_obj(obj) -> obj`.
- Server tool functions the gather layer calls (each returns `list[Finding]`; first arg is a platform client):
  - Defender `f0_defender_mcp.tools`: `get_secure_score(gc)`, `list_incidents(gc, severity_min=..., limit=...)`, `hunt(gc, ...)`
  - Entra `f0_entra_mcp.tools`: `list_conditional_access_policies(gc)`, `list_privileged_role_assignments(gc, limit=...)`
  - Intune `f0_intune_mcp.tools`: `get_compliance_summary(gc)`, `list_configuration_profiles(gc, limit=...)`
  - Purview `f0_purview_mcp.tools`: `get_dlp_summary(gc, hours_back=...)`
  - Tenable `f0_tenable_mcp.tools`: `get_vulnerability_summary(tio)`, `list_top_vulnerabilities(tio, ...)`
  - ProjectAchilles read `f0_projectachilles_mcp.tools`: `get_defense_score(pa, days=...)`, `get_weak_techniques(pa, days=..., limit=...)`, `get_fleet_health(pa)`
  - LimaCharlie `f0_limacharlie_mcp.tools`: `get_org_overview(lc)`, `list_detections(lc, ...)`, `query_telemetry(lc, ...)` — **synchronous** functions (LimaCharlie SDK); call via `asyncio.to_thread` (see `scripts/live_smoke_limacharlie.py`).
- Client construction recipe (mirror the `scripts/live_smoke_*.py` scripts exactly):
  - Graph platforms: `PlatformConfig.from_env("DEFENDER"|"ENTRA"|"INTUNE"|"PURVIEW")` then `async with GraphClient(cfg) as gc:`
  - Tenable: `TenableClient(TenableConfig.from_env())` (async ctx mgr `tio`)
  - ProjectAchilles: `ProjectAchillesClient(ProjectAchillesConfig.from_env())` (async ctx mgr `pa`)
  - LimaCharlie: `LimaCharlieClient(LimaCharlieConfig.from_env())` (sync `lc`)

---

## File Structure

```
core/f0_sectools_core/reports/
  __init__.py        # public API: build_report, to_pdf, types, Persona/Lang re-exports
  content.py         # intermediate representation: ReportContent, Section, MetricCard, ScopeMeta, BlockKind, ReportOutput
  i18n.py            # Lang, LABELS (en+es), label()
  sections.py        # FindingGroup, SectionSpec, SECTION_MAPS, group_findings(), is_not_assessed()
  narrative.py       # parse_narrative(text) -> Narrative
  theme.py           # brand tokens, inline_css(tier) -> str
  assets/report.css  # print CSS (two tiers)
  emit.py            # to_markdown(content) -> str ; to_html(content) -> str
  builder.py         # build_report(persona, language, narrative, findings, scope_meta) -> ReportOutput
  pdf.py             # to_pdf(html) -> bytes  (WeasyPrint, import-guarded)

core/tests/
  test_reports_content.py
  test_reports_i18n.py
  test_reports_sections.py
  test_reports_narrative.py
  test_reports_theme.py
  test_reports_emit.py
  test_reports_builder.py       # golden-structure per persona x lang
  test_reports_pdf.py
  fixtures/reports/
    findings_ciso.json          # neutral fixture findings
    narrative_ciso_en.md
    narrative_ciso_es.md
    golden_ciso_en.md           # frozen expected output
    golden_ciso_es.md
    ... (per persona x lang, added in Task 7)

scripts/
  gen_report.py       # CLI
  report_gather.py     # per-persona gather map (platform-aware)
  tests/
    test_gen_report.py

skills/reports/generate-report/
  SKILL.md
  references/narrative-template.md
```

---

### Task 1: Package scaffold + content IR

**Files:**
- Create: `core/f0_sectools_core/reports/__init__.py`
- Create: `core/f0_sectools_core/reports/content.py`
- Test: `core/tests/test_reports_content.py`

**Interfaces:**
- Produces (consumed by every later task):
  - `BlockKind` (StrEnum): `narrative, metric_grid, finding_rollup, finding_table, coverage, open_questions, provenance`
  - `MetricCard(label: str, value: str, state: str)` — frozen dataclass
  - `Section(kind: BlockKind, title: str, tier: str, text: str = "", items: list[str] = [], metrics: list[MetricCard] = [], findings: list[Finding] = [])` — frozen dataclass
  - `ScopeMeta(generated_at: str, tenant_label: str, window_label: str, platforms_queried: list[str], findings_count: int, assessed: list[str], not_assessed: list[str], pillar_metrics: list[MetricCard] = [])` — frozen dataclass
  - `ReportContent(persona: str, language: str, tier: str, title: str, subtitle: str, sections: list[Section])` — frozen dataclass
  - `ReportOutput(markdown: str, html: str)` — frozen dataclass

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_reports_content.py
from f0_sectools_core.reports.content import (
    BlockKind, MetricCard, Section, ScopeMeta, ReportContent, ReportOutput,
)


def test_section_defaults_are_independent():
    a = Section(kind=BlockKind.coverage, title="Scope", tier="executive")
    b = Section(kind=BlockKind.coverage, title="Scope", tier="executive")
    assert a.items == [] and a.metrics == [] and a.findings == []
    # frozen dataclass with default_factory: mutating one must not leak to the other
    assert a.items is not b.items


def test_metric_card_and_report_output_shapes():
    card = MetricCard(label="Config hardening", value="62%", state="needs-work")
    assert (card.label, card.value, card.state) == ("Config hardening", "62%", "needs-work")
    out = ReportOutput(markdown="# hi", html="<h1>hi</h1>")
    assert out.markdown == "# hi" and out.html == "<h1>hi</h1>"


def test_report_content_carries_ordered_sections():
    s1 = Section(kind=BlockKind.narrative, title="Summary", tier="executive", text="ok")
    content = ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Executive Risk Briefing", subtitle="Prepared for the CISO",
        sections=[s1],
    )
    assert content.sections[0].kind is BlockKind.narrative
    assert [s.title for s in content.sections] == ["Summary"]


def test_scope_meta_fields():
    meta = ScopeMeta(
        generated_at="2026-07-24 14:22", tenant_label="Contoso",
        window_label="Trailing 7 days", platforms_queried=["defender"],
        findings_count=3, assessed=["Config hardening"], not_assessed=["Data risk"],
    )
    assert meta.findings_count == 3
    assert meta.pillar_metrics == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_reports_content.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_sectools_core.reports'`

- [ ] **Step 3: Write the package scaffold and content IR**

```python
# core/f0_sectools_core/reports/__init__.py
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
```

```python
# core/f0_sectools_core/reports/content.py
"""Intermediate representation for a report.

One model, two emitters (emit.to_markdown / emit.to_html) so Markdown and PDF
never drift. A Section carries exactly one payload shape, selected by its kind.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from f0_sectools_core.schema.findings import Finding


class BlockKind(StrEnum):
    narrative = "narrative"          # model prose (redacted at emit)
    metric_grid = "metric_grid"      # executive big-number cards
    finding_rollup = "finding_rollup"  # CISO top-risks, rendered via persona renderer
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest core/tests/test_reports_content.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Verify types and lint**

Run: `uv run mypy core/f0_sectools_core/reports/ && uv run ruff check core/f0_sectools_core/reports/`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add core/f0_sectools_core/reports/__init__.py core/f0_sectools_core/reports/content.py core/tests/test_reports_content.py
git commit -F <commit-msg-file>   # message: "feat(reports): report content IR (Section/ReportContent/ScopeMeta)"
```

---

### Task 2: i18n label table

**Files:**
- Create: `core/f0_sectools_core/reports/i18n.py`
- Test: `core/tests/test_reports_i18n.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Lang = Literal["en", "es"]`
  - `LABELS: dict[str, dict[str, str]]` keyed `LABELS[lang][key]`
  - `label(lang: str, key: str) -> str` — raises `KeyError` on unknown lang or key.
  - Required keys (both languages must define all): `report_title_executive, report_title_operational, prepared_for_ciso, prepared_for_detection_engineer, prepared_for_threat_hunter, prepared_for_security_engineer, generated_locally, sec_executive_summary, sec_posture, sec_top_risks, sec_findings, sec_scope, sec_open_questions, sec_provenance, assessed, not_assessed, state_strong, state_needs_work, state_exposure, state_not_assessed, provenance_platforms, provenance_findings, provenance_redacted, no_findings, open_questions_intro`

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_reports_i18n.py
import pytest

from f0_sectools_core.reports.i18n import LABELS, label


def test_en_and_es_have_identical_keys():
    assert set(LABELS["en"]) == set(LABELS["es"]), (
        f"key drift: only-en={set(LABELS['en']) - set(LABELS['es'])}, "
        f"only-es={set(LABELS['es']) - set(LABELS['en'])}"
    )


def test_no_label_is_empty():
    for lang, table in LABELS.items():
        for key, value in table.items():
            assert value.strip(), f"empty label {lang}/{key}"


def test_label_lookup_and_errors():
    assert label("en", "not_assessed") == "Not assessed"
    assert label("es", "not_assessed") == "No evaluado"
    with pytest.raises(KeyError):
        label("en", "nonexistent_key")
    with pytest.raises(KeyError):
        label("fr", "not_assessed")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_reports_i18n.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Write the i18n module**

```python
# core/f0_sectools_core/reports/i18n.py
"""Deterministic label table for report chrome, English and Spanish.

Only the fixed labels live here; the persona agent authors the narrative prose
in the chosen language. A test asserts en/es key-parity so no translation is
silently missing.
"""
from __future__ import annotations

from typing import Literal

Lang = Literal["en", "es"]

LABELS: dict[str, dict[str, str]] = {
    "en": {
        "report_title_executive": "Executive Risk Briefing",
        "report_title_operational": "Security Operations Report",
        "prepared_for_ciso": "Prepared for the CISO",
        "prepared_for_detection_engineer": "Prepared for Detection Engineering",
        "prepared_for_threat_hunter": "Prepared for Threat Hunting",
        "prepared_for_security_engineer": "Prepared for Security Engineering",
        "generated_locally": "Generated locally by f0_sectools",
        "sec_executive_summary": "Executive summary",
        "sec_posture": "Posture at a glance",
        "sec_top_risks": "Top risks",
        "sec_findings": "Findings",
        "sec_scope": "Scope & coverage",
        "sec_open_questions": "Open questions",
        "sec_provenance": "Provenance",
        "assessed": "Assessed",
        "not_assessed": "Not assessed",
        "state_strong": "strong",
        "state_needs_work": "needs work",
        "state_exposure": "exposure",
        "state_not_assessed": "not assessed",
        "provenance_platforms": "platforms queried",
        "provenance_findings": "findings",
        "provenance_redacted": "all data redacted at source · no external calls",
        "no_findings": "No findings in this window.",
        "open_questions_intro": "For you to weigh in — not for the tool to answer:",
    },
    "es": {
        "report_title_executive": "Informe Ejecutivo de Riesgo",
        "report_title_operational": "Informe de Operaciones de Seguridad",
        "prepared_for_ciso": "Preparado para el CISO",
        "prepared_for_detection_engineer": "Preparado para Ingeniería de Detección",
        "prepared_for_threat_hunter": "Preparado para Caza de Amenazas",
        "prepared_for_security_engineer": "Preparado para Ingeniería de Seguridad",
        "generated_locally": "Generado localmente por f0_sectools",
        "sec_executive_summary": "Resumen ejecutivo",
        "sec_posture": "Postura de un vistazo",
        "sec_top_risks": "Riesgos principales",
        "sec_findings": "Hallazgos",
        "sec_scope": "Alcance y cobertura",
        "sec_open_questions": "Preguntas abiertas",
        "sec_provenance": "Procedencia",
        "assessed": "Evaluado",
        "not_assessed": "No evaluado",
        "state_strong": "sólido",
        "state_needs_work": "requiere atención",
        "state_exposure": "exposición",
        "state_not_assessed": "no evaluado",
        "provenance_platforms": "plataformas consultadas",
        "provenance_findings": "hallazgos",
        "provenance_redacted": "datos redactados en origen · sin llamadas externas",
        "no_findings": "No hay hallazgos en esta ventana.",
        "open_questions_intro": "Para su valoración — no para que la herramienta responda:",
    },
}


def label(lang: str, key: str) -> str:
    """Return the label for a language/key. Raises KeyError if either is unknown."""
    return LABELS[lang][key]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest core/tests/test_reports_i18n.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Types and lint**

Run: `uv run mypy core/f0_sectools_core/reports/i18n.py && uv run ruff check core/f0_sectools_core/reports/i18n.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add core/f0_sectools_core/reports/i18n.py core/tests/test_reports_i18n.py
git commit -m "feat(reports): en/es i18n label table with key-parity test"
```

---

### Task 3: Section maps + finding grouping

**Files:**
- Create: `core/f0_sectools_core/reports/sections.py`
- Test: `core/tests/test_reports_sections.py`

**Interfaces:**
- Consumes: `content.BlockKind`, `schema.findings.Finding/FindingType/Severity`.
- Produces:
  - `FindingGroup` (StrEnum): `posture, top_risks, detections, telemetry, exposure, identity, compliance, all`
  - `SectionSpec(kind: BlockKind, title_key: str, tier: str, group: FindingGroup | None)` — frozen dataclass. `title_key` is an i18n key; `group` is the finding bucket feeding a data section (None for narrative/provenance/coverage).
  - `TIER: dict[str, str]` mapping persona value → `"executive"|"operational"`.
  - `SECTION_MAPS: dict[str, list[SectionSpec]]` keyed by persona value, one entry per persona (`ciso, detection_engineer, threat_hunter, security_engineer`).
  - `is_not_assessed(f: Finding) -> bool` — True if `f` is a degradation posture finding (dark platform).
  - `group_findings(findings: list[Finding], persona: str) -> dict[FindingGroup, list[Finding]]` — buckets findings by source/type for the persona's section groups.
  - `DEGRADATION_MARKERS: tuple[str, ...]` — title substrings the schema factories emit for dark platforms.

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_reports_sections.py
from f0_sectools_core.reports.content import BlockKind
from f0_sectools_core.reports.sections import (
    FindingGroup, SECTION_MAPS, TIER, is_not_assessed, group_findings,
)
from f0_sectools_core.schema.findings import Finding, FindingType, Severity


def test_all_four_personas_have_maps():
    assert set(SECTION_MAPS) == {"ciso", "detection_engineer", "threat_hunter", "security_engineer"}


def test_ciso_is_executive_tier_and_has_expected_section_order():
    specs = SECTION_MAPS["ciso"]
    assert TIER["ciso"] == "executive"
    kinds = [s.kind for s in specs]
    assert kinds == [
        BlockKind.narrative,      # executive summary
        BlockKind.metric_grid,    # posture at a glance
        BlockKind.finding_rollup, # top risks
        BlockKind.coverage,       # scope & coverage
        BlockKind.open_questions,
        BlockKind.provenance,
    ]


def test_operational_personas_use_finding_table():
    for persona in ("detection_engineer", "threat_hunter", "security_engineer"):
        assert TIER[persona] == "operational"
        kinds = [s.kind for s in SECTION_MAPS[persona]]
        assert BlockKind.finding_table in kinds
        assert BlockKind.metric_grid not in kinds  # operational tier is finding-forward


def test_is_not_assessed_detects_permission_missing():
    dark = Finding.permission_missing("defender", "SecurityEvents.Read.All", "secure score")
    assert is_not_assessed(dark) is True
    real = Finding(source="defender", finding_type=FindingType.risk,
                   severity=Severity.high, title="Device compliance gap")
    assert is_not_assessed(real) is False


def test_group_findings_buckets_exposure_for_security_engineer():
    vuln = Finding(source="tenable", finding_type=FindingType.risk,
                   severity=Severity.critical, title="3 critical vulns exposed")
    grouped = group_findings([vuln], "security_engineer")
    assert vuln in grouped[FindingGroup.all]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_reports_sections.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Write the sections module**

```python
# core/f0_sectools_core/reports/sections.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest core/tests/test_reports_sections.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Types and lint**

Run: `uv run mypy core/f0_sectools_core/reports/sections.py && uv run ruff check core/f0_sectools_core/reports/sections.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add core/f0_sectools_core/reports/sections.py core/tests/test_reports_sections.py
git commit -m "feat(reports): per-persona section maps + finding grouping + not-assessed test"
```

---

### Task 4: Narrative parser

**Files:**
- Create: `core/f0_sectools_core/reports/narrative.py`
- Test: `core/tests/test_reports_narrative.py`

**Interfaces:**
- Consumes: nothing (pure string parsing).
- Produces:
  - `Narrative(executive_summary: str, risk_framing: str, open_questions: list[str])` — frozen dataclass.
  - `parse_narrative(text: str) -> Narrative` — parses `## Executive Summary`, `## Risk Framing`, `## Open Questions` (case-insensitive header match). Missing sections degrade to empty string / empty list. `Open Questions` body is split into a list: markdown list items (`- ` / `1. `) become one item each; if no list markers, non-blank lines each become an item.

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_reports_narrative.py
from f0_sectools_core.reports.narrative import Narrative, parse_narrative


def test_parses_all_three_sections():
    text = (
        "## Executive Summary\n"
        "Our posture is moderate and stable.\n\n"
        "## Risk Framing\n"
        "Device compliance is the biggest surface.\n\n"
        "## Open Questions\n"
        "- Is 61% device compliance acceptable?\n"
        "- Do we treat the overlap as one workstream?\n"
    )
    n = parse_narrative(text)
    assert "moderate and stable" in n.executive_summary
    assert "biggest surface" in n.risk_framing
    assert n.open_questions == [
        "Is 61% device compliance acceptable?",
        "Do we treat the overlap as one workstream?",
    ]


def test_missing_sections_degrade_gracefully():
    n = parse_narrative("## Executive Summary\nJust a summary.\n")
    assert n.executive_summary == "Just a summary."
    assert n.risk_framing == ""
    assert n.open_questions == []


def test_open_questions_without_list_markers_split_by_line():
    n = parse_narrative("## Open Questions\nFirst question?\nSecond question?\n")
    assert n.open_questions == ["First question?", "Second question?"]


def test_empty_input_yields_empty_narrative():
    n = parse_narrative("")
    assert n == Narrative(executive_summary="", risk_framing="", open_questions=[])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_reports_narrative.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Write the narrative parser**

```python
# core/f0_sectools_core/reports/narrative.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest core/tests/test_reports_narrative.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Types and lint**

Run: `uv run mypy core/f0_sectools_core/reports/narrative.py && uv run ruff check core/f0_sectools_core/reports/narrative.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add core/f0_sectools_core/reports/narrative.py core/tests/test_reports_narrative.py
git commit -m "feat(reports): tolerant narrative Markdown parser"
```

---

### Task 5: Theme + print CSS

**Files:**
- Create: `core/f0_sectools_core/reports/theme.py`
- Create: `core/f0_sectools_core/reports/assets/report.css`
- Test: `core/tests/test_reports_theme.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `inline_css(tier: str) -> str` — returns the full CSS (read from `assets/report.css`) plus a `:root` custom-property block selecting tier variants; used to inline styles into the HTML so the PDF is self-contained (no external asset fetch).
  - `TIERS: tuple[str, str] = ("executive", "operational")`.

**Design note:** The CSS ships as a data file inside the package; `inline_css` reads it via `importlib.resources` so it works from an installed wheel. The two tiers differ by a body class (`report--executive` / `report--operational`) that the emitter sets on the root element.

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_reports_theme.py
import pytest

from f0_sectools_core.reports.theme import TIERS, inline_css


def test_inline_css_returns_nonempty_with_page_rule():
    css = inline_css("executive")
    assert "@page" in css
    assert "report--executive" in css or "--tier" in css
    assert len(css) > 200


def test_both_tiers_produce_css():
    for tier in TIERS:
        assert "@page" in inline_css(tier)


def test_unknown_tier_rejected():
    with pytest.raises(ValueError):
        inline_css("bogus")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_reports_theme.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Write the CSS asset**

Create `core/f0_sectools_core/reports/assets/report.css` with the two-tier design system approved in the mockup (Executive tier: restraint, navy `#0f1830` + gold `#d4a24e` accent, big muted numbers; Operational tier: denser, severity color-bars). Full file:

```css
/* f0_sectools report theme — two tiers share brand + severity palette. */
:root {
  --navy: #0f1830;
  --gold: #d4a24e;
  --ink: #1a1f2b;
  --muted: #667;
  --rule: #eef0f4;
  --sev-critical: #a11;
  --sev-high: #a6641b;
  --sev-medium: #8a6d1b;
  --sev-low: #2f7d4f;
  --sev-info: #6e7781;
}
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body {
  font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
  color: var(--ink); line-height: 1.5; font-size: 12pt; margin: 0;
}
.report__cover {
  background: var(--navy); color: #fff; padding: 26px 30px;
  border-bottom: 3px solid var(--gold);
}
.report__kicker { font-size: 9pt; letter-spacing: 2.5px; color: var(--gold); font-weight: 700; }
.report__title { font-size: 22pt; font-weight: 600; margin-top: 10px; }
.report__subtitle { font-size: 11pt; color: #9fb0d0; margin-top: 10px; }
.report__section { padding: 20px 30px; border-top: 1px solid var(--rule); }
.report__h {
  font-size: 10pt; font-weight: 700; letter-spacing: .6px; text-transform: uppercase;
  color: #8892a6; margin: 0 0 10px;
}
/* Executive tier: big-number metric grid. */
.metric-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 18px 24px; }
.metric__value { font-size: 26pt; font-weight: 700; color: var(--navy); }
.metric__label { font-size: 10pt; color: var(--muted); }
.metric__state--strong { color: var(--sev-low); }
.metric__state--needs-work { color: var(--sev-high); }
.metric__state--exposure { color: var(--sev-critical); }
.metric__state--not-assessed { color: var(--muted); }
/* Operational tier: dense finding rows with a severity color-bar. */
.finding { border-left: 4px solid var(--sev-info); padding: 6px 10px; margin-bottom: 6px; background: #f6f8fa; }
.finding--critical { border-left-color: var(--sev-critical); background: #faf0f0; }
.finding--high { border-left-color: var(--sev-high); background: #fdf7e6; }
.finding--medium { border-left-color: var(--sev-medium); background: #fdf9ee; }
.finding--low { border-left-color: var(--sev-low); }
.finding__title { font-size: 11pt; font-weight: 700; }
.finding__meta { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 9pt; color: #666; margin-top: 2px; }
.oq { border-left: 3px solid var(--gold); background: #fdf8ef; padding: 10px 14px; margin: 8px 0; }
.coverage { background: #f8f9fb; }
.provenance { font-size: 9pt; color: #8892a6; }
.report--operational .report__title { font-size: 18pt; }
```

- [ ] **Step 4: Write the theme module**

```python
# core/f0_sectools_core/reports/theme.py
"""Load the packaged report CSS and select a tier.

The CSS is a package data file read via importlib.resources so it works from an
installed wheel. Inlining it into the HTML keeps the PDF self-contained (no
external asset fetch — the local-only guarantee).
"""
from __future__ import annotations

from importlib.resources import files

TIERS: tuple[str, str] = ("executive", "operational")


def inline_css(tier: str) -> str:
    if tier not in TIERS:
        raise ValueError(f"Unknown tier '{tier}'. Valid tiers: {', '.join(TIERS)}")
    css = (files("f0_sectools_core.reports.assets") / "report.css").read_text(encoding="utf-8")
    return css
```

- [ ] **Step 5: Ensure the CSS ships in the wheel**

The wheel build (`[tool.hatch.build.targets.wheel] packages = ["f0_sectools_core"]`) includes package data by default for hatchling. Confirm by running the test below (it reads via `importlib.resources`, which resolves from source tree during dev).

- [ ] **Step 6: Run test to verify it passes**

Run: `uv run pytest core/tests/test_reports_theme.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Types and lint**

Run: `uv run mypy core/f0_sectools_core/reports/theme.py && uv run ruff check core/f0_sectools_core/reports/theme.py`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add core/f0_sectools_core/reports/theme.py core/f0_sectools_core/reports/assets/report.css core/tests/test_reports_theme.py
git commit -m "feat(reports): two-tier print CSS + packaged theme loader"
```

---

### Task 6: Emitters (Markdown + HTML)

**Files:**
- Create: `core/f0_sectools_core/reports/emit.py`
- Test: `core/tests/test_reports_emit.py`

**Interfaces:**
- Consumes: `content.ReportContent/Section/BlockKind/MetricCard`, `renderers.render_findings`, `renderers.Persona`, `redaction.redact.redact_text`, `theme.inline_css`.
- Produces:
  - `to_markdown(content: ReportContent) -> str`
  - `to_html(content: ReportContent) -> str`
  - Both redact every emitted string via `redact_text`.

**Design:** One module, two emitters, sharing a per-block dispatch so MD and HTML stay in step. Data-block findings are rendered through the existing persona renderer (`render_findings`) for Markdown; for HTML the finding rows are emitted with severity CSS classes. `narrative` / `open_questions` blocks carry model prose → always redacted. `metric_grid` renders `MetricCard`s. `provenance` and `coverage` carry code-owned `items`/`text`.

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_reports_emit.py
from f0_sectools_core.reports.content import (
    BlockKind, MetricCard, ReportContent, Section,
)
from f0_sectools_core.reports.emit import to_html, to_markdown
from f0_sectools_core.schema.findings import Finding, FindingType, Severity


def _content() -> ReportContent:
    finding = Finding(source="tenable", finding_type=FindingType.risk,
                      severity=Severity.critical, title="3 critical vulns exposed")
    return ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Executive Risk Briefing", subtitle="Prepared for the CISO · Contoso",
        sections=[
            Section(BlockKind.narrative, "Executive summary", "executive",
                    text="Posture is moderate. Secret: sk-ABC123SECRETKEY0000."),
            Section(BlockKind.metric_grid, "Posture at a glance", "executive",
                    metrics=[MetricCard("Config hardening", "62%", "needs-work")]),
            Section(BlockKind.finding_rollup, "Top risks", "executive", findings=[finding]),
            Section(BlockKind.open_questions, "Open questions", "executive",
                    items=["Is 61% device compliance acceptable?"]),
            Section(BlockKind.provenance, "Provenance", "executive",
                    text="Generated 2026-07-24 · 8 platforms · 3 findings"),
        ],
    )


def test_markdown_has_title_sections_and_findings():
    md = to_markdown(_content())
    assert md.startswith("# Executive Risk Briefing")
    assert "## Posture at a glance" in md
    assert "62%" in md
    assert "3 critical vulns exposed" in md
    assert "Is 61% device compliance acceptable?" in md


def test_html_is_self_contained_and_has_severity_class():
    html = to_html(_content())
    assert "<style>" in html and "@page" in html          # inlined CSS
    assert "report--executive" in html
    assert "metric__value" in html
    assert "http" not in html.split("</style>")[0].replace("https://", "")  # no external URLs in head


def test_planted_secret_is_redacted_in_both_emitters():
    c = _content()
    md = to_markdown(c)
    html = to_html(c)
    assert "SECRETKEY0000" not in md
    assert "SECRETKEY0000" not in html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_reports_emit.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Write the emitters**

```python
# core/f0_sectools_core/reports/emit.py
"""Emit a ReportContent as Markdown or self-contained HTML.

Every string written passes through redact_text (narrative prose included).
Finding bodies reuse the persona renderers so presentation stays DRY. The HTML
inlines the theme CSS so the page — and the PDF WeasyPrint renders from it — has
no external dependencies (the local-only guarantee).
"""
from __future__ import annotations

import html as _html

from f0_sectools_core.redaction.redact import redact_text
from f0_sectools_core.renderers import Persona, render_findings

from .content import BlockKind, MetricCard, ReportContent, Section
from .theme import inline_css

_SEV_CLASS = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}


def _r(text: str) -> str:
    return redact_text(text)


def _persona(content: ReportContent) -> Persona:
    return Persona(content.persona)


# ── Markdown ─────────────────────────────────────────────────────────
def to_markdown(content: ReportContent) -> str:
    lines: list[str] = [f"# {_r(content.title)}", "", f"*{_r(content.subtitle)}*", ""]
    for s in content.sections:
        lines.append(f"## {_r(s.title)}")
        lines.append("")
        lines.extend(_md_body(s, content))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _md_body(s: Section, content: ReportContent) -> list[str]:
    if s.kind is BlockKind.metric_grid:
        return [f"- **{_r(m.label)}:** {_r(m.value)} ({_r(m.state)})" for m in s.metrics]
    if s.kind in (BlockKind.finding_rollup, BlockKind.finding_table):
        if not s.findings:
            return ["_No findings in this window._"]
        return [render_findings(s.findings, _persona(content))]
    if s.kind is BlockKind.open_questions:
        return [f"{i}. {_r(q)}" for i, q in enumerate(s.items, 1)]
    if s.kind is BlockKind.coverage:
        return [f"- {_r(item)}" for item in s.items] or [_r(s.text)]
    # narrative / provenance
    return [_r(s.text)]


# ── HTML ─────────────────────────────────────────────────────────────
def to_html(content: ReportContent) -> str:
    tier_class = f"report--{content.tier}"
    body: list[str] = [
        '<div class="report__cover">',
        '<div class="report__kicker">F0RT1KA · SECURITY POSTURE</div>',
        f'<div class="report__title">{_e(content.title)}</div>',
        f'<div class="report__subtitle">{_e(content.subtitle)}</div>',
        "</div>",
    ]
    for s in content.sections:
        body.append('<section class="report__section">')
        body.append(f'<div class="report__h">{_e(s.title)}</div>')
        body.extend(_html_body(s, content))
        body.append("</section>")
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<style>{inline_css(content.tier)}</style></head>"
        f"<body class='{tier_class}'>{''.join(body)}</body></html>"
    )


def _e(text: str) -> str:
    """Redact then HTML-escape."""
    return _html.escape(_r(text))


def _html_body(s: Section, content: ReportContent) -> list[str]:
    if s.kind is BlockKind.metric_grid:
        cards = "".join(_metric_card(m) for m in s.metrics)
        return [f'<div class="metric-grid">{cards}</div>']
    if s.kind in (BlockKind.finding_rollup, BlockKind.finding_table):
        if not s.findings:
            return ['<p><em>No findings in this window.</em></p>']
        return [_finding_row(f) for f in _sorted(s.findings)]
    if s.kind is BlockKind.open_questions:
        return [f'<div class="oq"><b>{i}.</b> {_e(q)}</div>' for i, q in enumerate(s.items, 1)]
    if s.kind is BlockKind.coverage:
        inner = "".join(f"<p>{_e(item)}</p>" for item in s.items) or f"<p>{_e(s.text)}</p>"
        return [f'<div class="coverage">{inner}</div>']
    if s.kind is BlockKind.provenance:
        return [f'<div class="provenance">{_e(s.text)}</div>']
    return [f"<p>{_e(s.text)}</p>"]


def _metric_card(m: MetricCard) -> str:
    state = m.state.replace(" ", "-")
    return (
        f'<div><div class="metric__value">{_e(m.value)}</div>'
        f'<div class="metric__label">{_e(m.label)} · '
        f'<span class="metric__state--{state}">{_e(m.state)}</span></div></div>'
    )


def _finding_row(f) -> str:  # noqa: ANN001  (Finding; scripts-free core keeps import cost low)
    sev = _SEV_CLASS.get(f.severity.value, "info")
    meta = f"{f.source} · {f.severity.value}"
    return (
        f'<div class="finding finding--{sev}">'
        f'<div class="finding__title">{_e(f.title)}</div>'
        f'<div class="finding__meta">{_e(meta)}</div></div>'
    )


def _sorted(findings):  # noqa: ANN001, ANN201
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: order.get(f.severity.value, 99))
```

**Note on `# noqa: ANN001`:** the two private helpers take a `Finding` but importing it only for an annotation is fine — prefer adding the real type. Replace `f` param annotations with `f: Finding` and import `Finding` from `f0_sectools_core.schema.findings`, and drop the `noqa`. (Kept explicit here so the engineer wires the import.)

- [ ] **Step 4: Fix the annotations properly**

Import `Finding` and annotate: `def _finding_row(f: Finding) -> str:` and `def _sorted(findings: list[Finding]) -> list[Finding]:`. Remove the `# noqa` comments. Re-run mypy.

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest core/tests/test_reports_emit.py -v`
Expected: PASS (3 passed)

- [ ] **Step 6: Types and lint**

Run: `uv run mypy core/f0_sectools_core/reports/emit.py && uv run ruff check core/f0_sectools_core/reports/emit.py`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add core/f0_sectools_core/reports/emit.py core/tests/test_reports_emit.py
git commit -m "feat(reports): Markdown + self-contained HTML emitters (redacted, renderer-reusing)"
```

---

### Task 7: Builder + golden-structure tests

**Files:**
- Create: `core/f0_sectools_core/reports/builder.py`
- Modify: `core/f0_sectools_core/reports/__init__.py` (export `build_report`)
- Test: `core/tests/test_reports_builder.py`
- Create fixtures: `core/tests/fixtures/reports/` (findings + narrative + frozen goldens per persona × lang)

**Interfaces:**
- Consumes: `content.*`, `sections.*`, `narrative.parse_narrative`, `emit.to_markdown/to_html`, `i18n.label`, `renderers.Persona`.
- Produces:
  - `build_report(persona: str, language: str, narrative: str, findings: list[Finding], scope_meta: ScopeMeta) -> ReportOutput`
  - Assembles a `ReportContent` from the persona's `SECTION_MAPS`, the parsed narrative, the grouped findings, and `scope_meta`; emits Markdown + HTML.

**Assembly rules (deterministic):**
- `persona` accepts underscore or hyphen; normalize hyphen→underscore, validate against `SECTION_MAPS`.
- Title = `label(lang, "report_title_executive"|"report_title_operational")` by tier.
- Subtitle = `label(lang, "prepared_for_<persona>") + " · " + tenant_label + " · " + window_label`.
- For each `SectionSpec`, build a `Section`:
  - `narrative` → `text = narrative.executive_summary` (fallback: a deterministic stub `label(lang,"no_findings")`-style line if empty).
  - `metric_grid` → `metrics = scope_meta.pillar_metrics`.
  - `finding_rollup` / `finding_table` → `findings = group_findings(findings, persona)[spec.group]`.
  - `coverage` → `items = ["<Assessed>: a, b, c", "<Not assessed>: x, y"]` from `scope_meta.assessed/not_assessed` using the i18n `assessed`/`not_assessed` labels.
  - `open_questions` → `items = narrative.open_questions` (fallback: single deterministic stub item).
  - `provenance` → `text = f"{generated_at} · {n} {provenance_platforms} · {findings_count} {provenance_findings} · {provenance_redacted}"`.
- Section title = `label(lang, spec.title_key)`.

- [ ] **Step 1: Write the failing test (structural, both languages)**

```python
# core/tests/test_reports_builder.py
import json
from pathlib import Path

from f0_sectools_core.reports import build_report
from f0_sectools_core.reports.content import MetricCard, ScopeMeta
from f0_sectools_core.schema.findings import Finding

FIX = Path(__file__).parent / "fixtures" / "reports"


def _findings() -> list[Finding]:
    data = json.loads((FIX / "findings_ciso.json").read_text())
    return [Finding.model_validate(d) for d in data]


def _scope() -> ScopeMeta:
    return ScopeMeta(
        generated_at="2026-07-24 14:22", tenant_label="Contoso",
        window_label="Trailing 7 days",
        platforms_queried=["defender", "tenable", "intune", "purview", "projectachilles", "limacharlie"],
        findings_count=3, assessed=["Config hardening", "Vulnerability exposure"],
        not_assessed=["Insider risk (not licensed)"],
        pillar_metrics=[MetricCard("Config hardening", "62%", "needs-work")],
    )


def test_ciso_en_report_structure():
    narrative = (FIX / "narrative_ciso_en.md").read_text()
    out = build_report("ciso", "en", narrative, _findings(), _scope())
    md = out.markdown
    # ordered executive section headings present
    for heading in ["Executive summary", "Posture at a glance", "Top risks",
                    "Scope & coverage", "Open questions", "Provenance"]:
        assert f"## {heading}" in md, heading
    assert "62%" in md
    assert "Not assessed: Insider risk (not licensed)" in md
    assert "2026-07-24 14:22" in md
    assert out.html.startswith("<!doctype html>")


def test_ciso_es_uses_spanish_labels():
    narrative = (FIX / "narrative_ciso_es.md").read_text()
    out = build_report("ciso", "es", narrative, _findings(), _scope())
    assert "## Resumen ejecutivo" in out.markdown
    assert "## Preguntas abiertas" in out.markdown
    assert "No evaluado:" in out.markdown


def test_hyphenated_persona_accepted():
    out = build_report("threat-hunter", "en", "## Executive Summary\nHi.\n", _findings(), _scope())
    assert "Prepared for Threat Hunting" in out.markdown


def test_golden_ciso_en_frozen():
    narrative = (FIX / "narrative_ciso_en.md").read_text()
    out = build_report("ciso", "en", narrative, _findings(), _scope())
    expected = (FIX / "golden_ciso_en.md").read_text()
    assert out.markdown == expected
```

- [ ] **Step 2: Create the neutral fixtures**

`core/tests/fixtures/reports/findings_ciso.json` (neutral values only):

```json
[
  {"source": "tenable", "finding_type": "risk", "severity": "critical",
   "title": "3 internet-exposed critical vulnerabilities",
   "evidence": [{"key": "cvss", "value": "9.8"}]},
  {"source": "intune", "finding_type": "risk", "severity": "high",
   "title": "39% of managed devices non-compliant"},
  {"source": "purview", "finding_type": "posture", "severity": "info",
   "title": "Insider Risk Management not licensed — insider-risk alerts unavailable",
   "recommended_action": {"summary": "License Insider Risk Management.", "confidence": "high"}}
]
```

`core/tests/fixtures/reports/narrative_ciso_en.md`:

```markdown
## Executive Summary
Our posture is moderate and stable. Two risks are live this week: internet-exposed critical vulnerabilities and a device-compliance gap.

## Risk Framing
The critical vulnerabilities are the fastest single reduction in breach likelihood; the compliance gap is the largest attack surface.

## Open Questions
- Is 61% device compliance acceptable against our risk appetite?
- Do we treat the vuln and compliance work as one prioritized workstream?
```

`core/tests/fixtures/reports/narrative_ciso_es.md`:

```markdown
## Resumen Ejecutivo
Nuestra postura es moderada y estable. Dos riesgos están activos esta semana: vulnerabilidades críticas expuestas a Internet y una brecha en el cumplimiento de dispositivos.

## Marco de Riesgo
Las vulnerabilidades críticas son la reducción más rápida de la probabilidad de brecha.

## Preguntas Abiertas
- ¿Es aceptable un 61% de cumplimiento de dispositivos según nuestro apetito de riesgo?
- ¿Tratamos el trabajo de vulnerabilidades y cumplimiento como un único flujo priorizado?
```

- [ ] **Step 3: Write the builder**

```python
# core/f0_sectools_core/reports/builder.py
"""Assemble a ReportContent from gathered findings + parsed narrative, and emit.

Deterministic and platform-free. The persona's SECTION_MAPS drives section order
and tier; each data section is filled from grouped findings; narrative sections
carry the agent's prose. build_report is the package's single public entry point.
"""
from __future__ import annotations

from f0_sectools_core.schema.findings import Finding

from . import emit
from .content import BlockKind, ReportContent, ReportOutput, Section, ScopeMeta
from .i18n import label
from .narrative import parse_narrative
from .sections import SECTION_MAPS, TIER, group_findings

_PERSONAS = set(SECTION_MAPS)


def _normalize_persona(persona: str) -> str:
    key = persona.replace("-", "_")
    if key not in _PERSONAS:
        valid = ", ".join(sorted(_PERSONAS))
        raise ValueError(f"Unknown persona '{persona}'. Valid: {valid}")
    return key


def _title(lang: str, tier: str) -> str:
    return label(lang, "report_title_executive" if tier == "executive" else "report_title_operational")


def _subtitle(lang: str, persona: str, meta: ScopeMeta) -> str:
    prepared = label(lang, f"prepared_for_{persona}")
    return f"{prepared} · {meta.tenant_label} · {meta.window_label} · {label(lang, 'generated_locally')}"


def _coverage_items(lang: str, meta: ScopeMeta) -> list[str]:
    items: list[str] = []
    if meta.assessed:
        items.append(f"{label(lang, 'assessed')}: {', '.join(meta.assessed)}")
    if meta.not_assessed:
        items.append(f"{label(lang, 'not_assessed')}: {', '.join(meta.not_assessed)}")
    return items


def _provenance_text(lang: str, meta: ScopeMeta) -> str:
    n_platforms = len(meta.platforms_queried)
    return (
        f"{meta.generated_at} · {n_platforms} {label(lang, 'provenance_platforms')} · "
        f"{meta.findings_count} {label(lang, 'provenance_findings')} · "
        f"{label(lang, 'provenance_redacted')}"
    )


def build_report(
    persona: str,
    language: str,
    narrative: str,
    findings: list[Finding],
    scope_meta: ScopeMeta,
) -> ReportOutput:
    persona = _normalize_persona(persona)
    tier = TIER[persona]
    parsed = parse_narrative(narrative)
    grouped = group_findings(findings, persona)

    sections: list[Section] = []
    for spec in SECTION_MAPS[persona]:
        title = label(language, spec.title_key)
        if spec.kind is BlockKind.narrative:
            text = parsed.executive_summary or label(language, "no_findings")
            sections.append(Section(spec.kind, title, spec.tier, text=text))
        elif spec.kind is BlockKind.metric_grid:
            sections.append(Section(spec.kind, title, spec.tier, metrics=list(scope_meta.pillar_metrics)))
        elif spec.kind in (BlockKind.finding_rollup, BlockKind.finding_table):
            group = grouped[spec.group] if spec.group is not None else []
            sections.append(Section(spec.kind, title, spec.tier, findings=list(group)))
        elif spec.kind is BlockKind.coverage:
            sections.append(Section(spec.kind, title, spec.tier, items=_coverage_items(language, scope_meta)))
        elif spec.kind is BlockKind.open_questions:
            items = parsed.open_questions or [label(language, "open_questions_intro")]
            sections.append(Section(spec.kind, title, spec.tier, items=items))
        elif spec.kind is BlockKind.provenance:
            sections.append(Section(spec.kind, title, spec.tier, text=_provenance_text(language, scope_meta)))

    content = ReportContent(
        persona=persona,
        language=language,
        tier=tier,
        title=_title(language, tier),
        subtitle=_subtitle(language, persona, scope_meta),
        sections=sections,
    )
    return ReportOutput(markdown=emit.to_markdown(content), html=emit.to_html(content))
```

- [ ] **Step 4: Export `build_report`**

Add to `core/f0_sectools_core/reports/__init__.py`:
```python
from .builder import build_report
```
and add `"build_report"` to `__all__`.

- [ ] **Step 5: Freeze the golden files**

Run the builder once to produce the golden output, inspect it, then save it:
```bash
uv run python -c "
import json, pathlib
from f0_sectools_core.reports import build_report
from f0_sectools_core.reports.content import MetricCard, ScopeMeta
from f0_sectools_core.schema.findings import Finding
FIX = pathlib.Path('core/tests/fixtures/reports')
findings = [Finding.model_validate(d) for d in json.loads((FIX/'findings_ciso.json').read_text())]
meta = ScopeMeta(generated_at='2026-07-24 14:22', tenant_label='Contoso', window_label='Trailing 7 days',
  platforms_queried=['defender','tenable','intune','purview','projectachilles','limacharlie'],
  findings_count=3, assessed=['Config hardening','Vulnerability exposure'],
  not_assessed=['Insider risk (not licensed)'], pillar_metrics=[MetricCard('Config hardening','62%','needs-work')])
out = build_report('ciso','en',(FIX/'narrative_ciso_en.md').read_text(),findings,meta)
(FIX/'golden_ciso_en.md').write_text(out.markdown)
print(out.markdown)
"
```
Eyeball the printed Markdown: correct headings, the metric line, the not-assessed line, the provenance stamp, no secrets. If good, the file is written. **Commit the golden as the frozen expectation.** (The `test_golden_ciso_en_frozen` test now compares byte-exact.)

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest core/tests/test_reports_builder.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Types and lint**

Run: `uv run mypy core/f0_sectools_core/reports/ && uv run ruff check core/f0_sectools_core/reports/`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add core/f0_sectools_core/reports/builder.py core/f0_sectools_core/reports/__init__.py core/tests/test_reports_builder.py core/tests/fixtures/reports/
git commit -m "feat(reports): build_report assembler + golden-structure tests (en/es)"
```

---

### Task 8: PDF export + `[reports]` extra

**Files:**
- Create: `core/f0_sectools_core/reports/pdf.py`
- Modify: `core/f0_sectools_core/reports/__init__.py` (export `to_pdf`)
- Modify: `core/pyproject.toml` (add optional `[reports]` extra)
- Test: `core/tests/test_reports_pdf.py`

**Interfaces:**
- Consumes: WeasyPrint (import-guarded).
- Produces: `to_pdf(html: str) -> bytes` — raises `ReportsPdfUnavailable` (subclass of `RuntimeError`) with an install hint if WeasyPrint is not importable.

- [ ] **Step 1: Write the failing test**

```python
# core/tests/test_reports_pdf.py
import pytest

from f0_sectools_core.reports.pdf import ReportsPdfUnavailable, to_pdf


def test_to_pdf_returns_pdf_bytes_when_weasyprint_present():
    weasyprint = pytest.importorskip("weasyprint")  # skip if system libs absent (e.g. CI)
    assert weasyprint is not None
    pdf = to_pdf("<!doctype html><html><body><h1>Hi</h1></body></html>")
    assert pdf[:4] == b"%PDF"


def test_missing_weasyprint_raises_clear_error(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "weasyprint":
            raise ModuleNotFoundError("No module named 'weasyprint'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ReportsPdfUnavailable) as ei:
        to_pdf("<html></html>")
    assert "f0-sectools-core[reports]" in str(ei.value)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest core/tests/test_reports_pdf.py -v`
Expected: FAIL — `ModuleNotFoundError` on `f0_sectools_core.reports.pdf`.

- [ ] **Step 3: Write the PDF module**

```python
# core/f0_sectools_core/reports/pdf.py
"""Render report HTML to PDF via WeasyPrint (optional dependency).

WeasyPrint is a pure-Python HTML/CSS -> PDF engine (no headless browser, no
external calls). It ships only in the `[reports]` extra so platform servers stay
lean; Markdown generation never depends on it.
"""
from __future__ import annotations


class ReportsPdfUnavailable(RuntimeError):
    """Raised when PDF export is requested but WeasyPrint is not installed."""


def to_pdf(html: str) -> bytes:
    try:
        import weasyprint
    except ModuleNotFoundError as e:
        raise ReportsPdfUnavailable(
            "PDF export needs WeasyPrint. Install it with: "
            "pip install 'f0-sectools-core[reports]'"
        ) from e
    return weasyprint.HTML(string=html).write_pdf()
```

- [ ] **Step 4: Export `to_pdf` and add the extra**

Add to `__init__.py`: `from .pdf import ReportsPdfUnavailable, to_pdf` and both names to `__all__`.

Add to `core/pyproject.toml` (after `dependencies`):
```toml
[project.optional-dependencies]
reports = ["weasyprint>=62"]
```

- [ ] **Step 5: Install the extra in the dev env and run the test**

Run: `uv pip install 'weasyprint>=62'` (or `uv sync --extra reports` if the workspace supports it)
Then: `uv run pytest core/tests/test_reports_pdf.py -v`
Expected: PASS if system libs (pango/cairo) present; the first test **skips** cleanly if WeasyPrint's native libs are missing; the second test always runs.

Note: if WeasyPrint can't be installed locally (missing system libs), the second test still passes; the `%PDF` test skips. Do not block the task on system-lib availability — the import-guard behavior is what CI verifies.

- [ ] **Step 6: Types and lint**

Run: `uv run mypy core/f0_sectools_core/reports/pdf.py && uv run ruff check core/f0_sectools_core/reports/pdf.py`
Expected: no errors. (mypy: `weasyprint` has no stubs — add `# type: ignore[import-untyped]` on the `import weasyprint` line if mypy complains, or add a `[[tool.mypy.overrides]]` `ignore_missing_imports` for `weasyprint` in the repo mypy config.)

- [ ] **Step 7: Commit**

```bash
git add core/f0_sectools_core/reports/pdf.py core/f0_sectools_core/reports/__init__.py core/pyproject.toml core/tests/test_reports_pdf.py
git commit -m "feat(reports): WeasyPrint PDF export as optional [reports] extra"
```

---

### Task 9: CLI + platform gather layer

**Files:**
- Create: `scripts/report_gather.py`
- Create: `scripts/gen_report.py`
- Test: `scripts/tests/test_gen_report.py`

**Interfaces:**
- `report_gather.py` produces:
  - `async def gather(persona: str, window_hours: int) -> tuple[list[Finding], ScopeMeta]` — constructs the persona's platform clients, calls each tool, collects findings, classifies assessed/not-assessed, builds the CISO metric grid, returns `(findings, scope_meta)`.
  - `GATHER_MAP: dict[str, list[GatherSpec]]` — per-persona list of `(platform, coro_factory, pillar_label)`.
  - Must be import-safe without any `.env` present (client construction is deferred to call time, wrapped in try/except → degradation finding).
- `gen_report.py` produces: the CLI (argparse) described in the spec.

**Design:** `scripts/` may import `servers/*` (dependency direction allows it — scripts sit above both). Each gatherer mirrors the matching `scripts/live_smoke_*.py` client construction. A platform that raises (missing creds / auth / permission) is caught and converted to a `Finding.permission_missing`-style posture finding so the report still generates (graceful-partial). **This is glue code and is mypy-exempt (scripts/ excluded from strict typing) — but it must be tested offline with fakes.**

- [ ] **Step 1: Write the failing test (offline, fakes — no real platform)**

```python
# scripts/tests/test_gen_report.py
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/ importable
import report_gather  # noqa: E402
from f0_sectools_core.reports.content import ScopeMeta  # noqa: E402
from f0_sectools_core.schema.findings import Finding, FindingType, Severity  # noqa: E402


def test_gather_degrades_when_platform_unconfigured(monkeypatch):
    # Force every pillar factory to raise (no creds) → all not-assessed, still returns.
    async def boom(window_hours):
        raise ValueError("Missing required environment variables: DEFENDER_TENANT_ID")

    monkeypatch.setattr(report_gather, "_PILLAR_FACTORIES",
                        {"Config hardening": boom, "Vulnerability exposure": boom})
    findings, meta = asyncio.run(report_gather.gather("ciso", 168))
    assert isinstance(meta, ScopeMeta)
    assert set(meta.not_assessed) >= {"Config hardening", "Vulnerability exposure"}
    assert meta.assessed == []  # nothing came back healthy
    # every dark pillar still produced a posture finding
    assert all(f.finding_type is FindingType.posture for f in findings)


def test_gather_collects_healthy_pillar(monkeypatch):
    async def ok(window_hours):
        return [Finding(source="defender", finding_type=FindingType.posture,
                        severity=Severity.info, title="Secure Score: 62%",
                        evidence=[{"key": "secure_score_pct", "value": "62"}])]

    monkeypatch.setattr(report_gather, "_PILLAR_FACTORIES", {"Config hardening": ok})
    findings, meta = asyncio.run(report_gather.gather("ciso", 168))
    assert "Config hardening" in meta.assessed
    assert any("62%" in f.title for f in findings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest scripts/tests/test_gen_report.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'report_gather'`.

- [ ] **Step 3: Write the gather layer**

Write `scripts/report_gather.py`. **Copy the exact client class/module import lines from the matching `scripts/live_smoke_<platform>.py` script** for each pillar (e.g. `live_smoke_tenable.py` for the Tenable client, `live_smoke_projectachilles.py` for the PA client, `live_smoke_limacharlie.py` for the LimaCharlie client) — those scripts already have the correct, live-validated import paths, so do not hand-guess module names. Structure (complete for the CISO pillars; operational personas follow the same pattern with their tool lists from the Reference section):

```python
# scripts/report_gather.py
"""Platform-aware finding gather for reports. Lives in scripts/ (may import
servers/*); core/reports stays platform-free. Each pillar factory mirrors the
matching live_smoke_*.py client construction. A platform that raises degrades to
a posture finding so the report still generates (graceful-partial)."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from dotenv import load_dotenv

from f0_sectools_core.reports.content import MetricCard, ScopeMeta
from f0_sectools_core.reports.sections import is_not_assessed
from f0_sectools_core.schema.findings import Finding, FindingType, Severity


def _degraded(pillar: str, detail: str) -> Finding:
    return Finding(
        source=pillar.lower().replace(" ", "_"),
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"{pillar} not configured — pillar not assessed",
        recommended_action=None,
    )


# ── CISO pillar factories (each returns list[Finding]) ───────────────
async def _pillar_config_hardening(window_hours: int) -> list[Finding]:
    from f0_defender_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.defender")
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return await tools.get_secure_score(gc)


async def _pillar_vuln_exposure(window_hours: int) -> list[Finding]:
    from f0_tenable_mcp import tools
    from f0_tenable_mcp.client import TenableClient, TenableConfig
    load_dotenv(".env.tenable")
    async with TenableClient(TenableConfig.from_env()) as tio:
        return await tools.get_vulnerability_summary(tio)


async def _pillar_device_compliance(window_hours: int) -> list[Finding]:
    from f0_intune_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.intune")
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return await tools.get_compliance_summary(gc)


async def _pillar_data_risk(window_hours: int) -> list[Finding]:
    from f0_purview_mcp import tools
    from f0_sectools_core.auth.config import PlatformConfig
    from f0_sectools_core.auth.graph import GraphClient
    load_dotenv(".env.purview")
    cfg = PlatformConfig.from_env("PURVIEW")
    async with GraphClient(cfg) as gc:
        return await tools.get_dlp_summary(gc, hours_back=window_hours)


async def _pillar_attack_validation(window_hours: int) -> list[Finding]:
    from f0_projectachilles_mcp import tools
    from f0_projectachilles_mcp.client import ProjectAchillesClient, ProjectAchillesConfig
    load_dotenv(".env.projectachilles")
    async with ProjectAchillesClient(ProjectAchillesConfig.from_env()) as pa:
        return await tools.get_defense_score(pa)


async def _pillar_endpoint_coverage(window_hours: int) -> list[Finding]:
    from f0_limacharlie_mcp import tools
    from f0_limacharlie_mcp.client import LimaCharlieClient, LimaCharlieConfig
    load_dotenv(".env.limacharlie")
    lc = LimaCharlieClient(LimaCharlieConfig.from_env())
    return await asyncio.to_thread(tools.get_org_overview, lc)


# pillar label -> factory. Patched in tests.
_PILLAR_FACTORIES: dict[str, Callable[[int], Awaitable[list[Finding]]]] = {
    "Config hardening": _pillar_config_hardening,
    "Attack validation": _pillar_attack_validation,
    "Vulnerability exposure": _pillar_vuln_exposure,
    "Device compliance": _pillar_device_compliance,
    "Data risk": _pillar_data_risk,
    "Endpoint coverage": _pillar_endpoint_coverage,
}

# Map a pillar's healthy finding to a big-number MetricCard. Best-effort: reads a
# conventional evidence key, falls back to the finding title.
_PILLAR_METRIC_KEY = {
    "Config hardening": "secure_score_pct",
    "Attack validation": "defense_score",
    "Vulnerability exposure": "critical_count",
    "Device compliance": "compliant_pct",
    "Data risk": "alert_count",
    "Endpoint coverage": "online_sensors",
}


def _metric_from(pillar: str, findings: list[Finding]) -> MetricCard:
    real = [f for f in findings if not is_not_assessed(f)]
    if not real:
        return MetricCard(pillar, "not assessed", "not-assessed")
    f = real[0]
    key = _PILLAR_METRIC_KEY.get(pillar, "")
    value = next((e.value for e in f.evidence if e.key == key), f.title)
    state = {"critical": "exposure", "high": "needs-work", "medium": "needs-work"}.get(
        f.severity.value, "strong")
    return MetricCard(pillar, value, state)


async def _run_pillar(pillar: str, factory, window_hours: int) -> tuple[str, list[Finding]]:
    try:
        return pillar, await factory(window_hours)
    except Exception as exc:  # noqa: BLE001 — any platform failure degrades, never aborts
        return pillar, [_degraded(pillar, str(exc))]


async def gather(persona: str, window_hours: int) -> tuple[list[Finding], ScopeMeta]:
    persona = persona.replace("-", "_")
    # v1: all personas gather the six pillars (shared engine); operational personas
    # additionally could gather detail tools — extend GATHER_MAP later.
    results = await asyncio.gather(*[
        _run_pillar(pillar, factory, window_hours)
        for pillar, factory in _PILLAR_FACTORIES.items()
    ])
    findings: list[Finding] = []
    assessed: list[str] = []
    not_assessed: list[str] = []
    metrics: list[MetricCard] = []
    for pillar, pillar_findings in results:
        findings.extend(pillar_findings)
        healthy = [f for f in pillar_findings if not is_not_assessed(f)]
        if healthy:
            assessed.append(pillar)
        else:
            not_assessed.append(pillar)
        metrics.append(_metric_from(pillar, pillar_findings))
    meta = ScopeMeta(
        generated_at="",  # stamped by the CLI
        tenant_label="",
        window_label=f"Trailing {window_hours // 24} days" if window_hours >= 24 else f"Trailing {window_hours}h",
        platforms_queried=[p.lower().replace(" ", "_") for p in _PILLAR_FACTORIES],
        findings_count=len(findings),
        assessed=assessed,
        not_assessed=not_assessed,
        pillar_metrics=metrics,
    )
    return findings, meta
```

**Note:** the test monkeypatches `_PILLAR_FACTORIES`; `gather` iterates that dict, so patching to two entries scopes the run. Confirm `_run_pillar`'s broad `except` converts a raising factory into a `_degraded` posture finding, which `is_not_assessed` must classify as not-assessed. **Important:** `_degraded`'s title uses the marker "not configured" so `is_not_assessed` returns True — verify the marker is in `DEGRADATION_MARKERS` (it is).

- [ ] **Step 4: Write the CLI**

```python
# scripts/gen_report.py
"""CLI: generate a persona posture report (Markdown + optional PDF, en/es).

Re-gathers findings deterministically via report_gather (no MCP round-trip),
parses the agent-authored narrative, builds the report, writes <out>.md and
optionally <out>.pdf. Local-only; nothing leaves the host."""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
from datetime import datetime, timezone
from pathlib import Path

import report_gather

from f0_sectools_core.reports import build_report, to_pdf
from f0_sectools_core.reports.pdf import ReportsPdfUnavailable

_PERSONAS = ("ciso", "threat-hunter", "detection-engineer", "security-engineer")
_LANGS = ("en", "es")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate a persona security posture report.")
    p.add_argument("--persona", required=True, choices=_PERSONAS)
    p.add_argument("--lang", default="en", choices=_LANGS)
    p.add_argument("--narrative", required=True, type=Path, help="Agent-authored narrative Markdown file.")
    p.add_argument("--window-hours", type=int, default=168)
    p.add_argument("--tenant-label", default="the organization")
    p.add_argument("--out", required=True, type=Path, help="Output basepath (writes <out>.md, <out>.pdf).")
    p.add_argument("--pdf", action="store_true")
    return p.parse_args()


async def _main() -> None:
    args = _parse_args()
    narrative = args.narrative.read_text(encoding="utf-8")
    findings, meta = await report_gather.gather(args.persona, args.window_hours)
    meta = dataclasses.replace(
        meta,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        tenant_label=args.tenant_label,
    )
    out = build_report(args.persona, args.lang, narrative, findings, meta)
    md_path = args.out.with_suffix(".md")
    md_path.write_text(out.markdown, encoding="utf-8")
    print(f"wrote {md_path}")
    if args.pdf:
        try:
            pdf = to_pdf(out.html)
        except ReportsPdfUnavailable as e:
            print(f"PDF skipped: {e}")
        else:
            pdf_path = args.out.with_suffix(".pdf")
            pdf_path.write_bytes(pdf)
            print(f"wrote {pdf_path}")


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest scripts/tests/test_gen_report.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Lint (scripts are mypy-exempt)**

Run: `uv run ruff check scripts/report_gather.py scripts/gen_report.py`
Expected: no errors. (Do NOT run mypy on scripts/ — excluded by design; if the repo's `ruff` config flags `BLE001`/`ANN`, the noqa comments handle the intended broad excepts.)

- [ ] **Step 7: Verify import-safety without env**

Run: `uv run python -c "import sys, pathlib; sys.path.insert(0, 'scripts'); import report_gather, gen_report; print('import ok')"`
Expected: `import ok` (module import must not touch `.env` or construct clients).

- [ ] **Step 8: Commit**

```bash
git add scripts/report_gather.py scripts/gen_report.py scripts/tests/test_gen_report.py
git commit -m "feat(reports): gen_report CLI + platform gather layer (graceful-partial, offline-tested)"
```

---

### Task 10: The `generate-report` skill

**Files:**
- Create: `skills/reports/generate-report/SKILL.md`
- Create: `skills/reports/generate-report/references/narrative-template.md`
- Test: `skills/test_skills_valid.py` (existing — must still pass)

**Interfaces:**
- Consumes: nothing (documentation). Refers to tools by base name; drives the agent to gather → author narrative → run `gen_report.py`.
- Constraint: frontmatter `description` **≤ 60 chars**; valid `name`, `version`.

- [ ] **Step 1: Write the SKILL.md**

```markdown
---
name: generate-report
description: Persona posture report (MD+PDF, EN/ES) from findings
version: 1.0.0
metadata:
  hermes:
    tags: [security, report, posture, ciso, deliverable]
    category: security
---

# Generate a Persona Posture Report

## When to Use

The operator wants a **shareable report** — a deliverable to open a conversation,
not a chat answer. Triggers: "generate my report", "build a CISO briefing",
"posture report I can send", "informe de postura". Produces Markdown (always) and
PDF (optional), in English or Spanish.

Pick the persona from the operator's role/lens:
- **ciso** — executive risk briefing (six-pillar posture, big numbers, restraint)
- **detection-engineer** — detection coverage + tuning questions
- **threat-hunter** — telemetry/incidents + hypothesis questions
- **security-engineer** — hardening backlog across identity/compliance/exposure

## Procedure

1. **Gather the findings** for the persona (read-only). For **ciso**, use the
   `roll-up-ciso-risk` skill's six pillars. Ground everything in what the tools
   actually return; a dark platform is "not assessed", never guessed.
2. **Author the narrative file** in the chosen language, using
   `references/narrative-template.md`. Fill three sections: `## Executive Summary`
   (the one-paragraph "so what"), `## Risk Framing` (per-risk notes), and
   `## Open Questions` (2–4 questions **for the operator to answer** — the
   conversation starter). Write only what the gathered findings support.
3. **Generate** (shell-capable runtimes): run
   `uv run python scripts/gen_report.py --persona <persona> --lang <en|es>
   --narrative <file> --window-hours <N> --tenant-label "<label>" --out <path> [--pdf]`.
   The script re-gathers the data deterministically (fresh, redacted) — your
   narrative supplies judgment, the script supplies the numbers.
4. **Hand back** the written path and a one-line summary. If the runtime has no
   shell, hand the operator the exact command to run.

## Pitfalls

- **Don't put numbers in the narrative.** The data sections come from the
  re-gather; the narrative is judgment (summary, framing, questions). A number
  you type is not grounded.
- **Open questions are for the operator, not rhetorical.** End with real
  decisions the operator must weigh (risk appetite, prioritization, blind spots).
- **PDF is optional.** If WeasyPrint isn't installed the script still writes the
  Markdown and prints an install hint; report that honestly.
- **One language per run.** Author the narrative in the same language you pass to
  `--lang`; the deterministic labels switch automatically.

## Verification

- The command prints `wrote <path>.md` (and `wrote <path>.pdf` with `--pdf`).
- The report ends with an **Open questions** section and a **Provenance** stamp.
- Any "not assessed" pillars name the dark platform explicitly.
```

- [ ] **Step 2: Write the narrative template**

```markdown
<!-- skills/reports/generate-report/references/narrative-template.md -->
# Narrative template

Copy this, fill each section in the operator's language, save as a .md file, and
pass it to `gen_report.py --narrative`. Keep it grounded strictly in gathered
findings — no numbers you didn't read from a tool.

## Executive Summary
<!-- One paragraph: the overall read and the 1-2 risks that matter this window. -->

## Risk Framing
<!-- A few lines per top risk: why it matters, what it intersects. Optional. -->

## Open Questions
<!-- 2-4 questions FOR THE OPERATOR to answer. Real decisions, not rhetorical. -->
- 
- 
```

- [ ] **Step 3: Run the skills validity test**

Run: `uv run pytest skills/test_skills_valid.py -v`
Expected: PASS (the new skill has valid frontmatter and a ≤60-char description — "Persona posture report (MD+PDF, EN/ES) from findings" is 51 chars).

- [ ] **Step 4: Commit**

```bash
git add skills/reports/generate-report/
git commit -m "feat(reports): generate-report skill + narrative template"
```

---

### Task 11: Docs regeneration + runtime wiring

**Files:**
- Modify: `CLAUDE.md` (Architecture tree: add `core/reports/` + `skills/reports/`; note the report feature in the relevant section)
- Modify: `README.md` (feature/status line if the repo lists features)
- Run + commit generated output: `docs/reference/` via `scripts/gen_docs.py`
- Modify: opencode skill symlink farm `.opencode/skills/` (add a symlink for the new skill, matching the existing pattern) + persona agents if they enumerate skills
- Verify: `scripts/tests/test_gen_docs.py`, `skills/test_skills_valid.py`, `integrations/test_integrations_valid.py`, full suite

**Interfaces:** none (docs/wiring only). Follows the "change code → regenerate → commit" reflex from CLAUDE.md.

- [ ] **Step 1: Add the reports package + skill to the CLAUDE.md architecture tree**

In the `core/` block add `reports/  # persona posture reports: builder, emit, pdf, theme, i18n`. In the `skills/` block add `reports/  # generate-report`. Keep it one line each; do not restate the design.

- [ ] **Step 2: Wire the skill into opencode**

Inspect `.opencode/skills/` for the existing symlink pattern:
```bash
ls -la .opencode/skills/ | head
```
Create a matching symlink for `generate-report` pointing into `skills/reports/generate-report` (relative symlink, same style as the others). If persona agents in `.opencode/agents/` enumerate available skills, add `generate-report` where the CISO/operational agents list theirs.

- [ ] **Step 3: Regenerate the reference docs**

Run: `uv run python scripts/gen_docs.py`
This regenerates `docs/reference/skills.md` (now 26 skills) and any tool catalogs. Review the diff.

- [ ] **Step 4: Run all drift guards + full suite**

Run:
```bash
uv run pytest scripts/tests/test_gen_docs.py skills/test_skills_valid.py integrations/test_integrations_valid.py -v
uv run pytest -q
uv run ruff check .
uv run mypy core/ servers/
```
Expected: all pass. If `test_gen_docs.py` fails, the generated docs weren't committed — re-run `gen_docs.py` and stage the output.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md docs/reference/ .opencode/skills/ .opencode/agents/
git commit -m "docs(reports): wire generate-report into catalog, CLAUDE.md tree, opencode"
```

---

## Post-implementation (not tasks — for the operator)

- **Live validation (user-gated):** with real `.env.*` present, generate a CISO report EN + ES against the tenant, eyeball the PDF, confirm "not assessed" pillars render correctly. This hits live platforms → requires explicit operator go-ahead (never run autonomously).
- **PDF system libs:** WeasyPrint needs pango/cairo on the host; document the install in the user guide when wiring live use.

## Out of scope (v1)

Charts/gauges, scheduled/trend reporting, report storage/diffing, distribution (emailing/uploading). The report writes to disk; distribution is the operator's.
```
