# Per-Persona Titles, Operational At-a-Glance & Translated Tile Chrome — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each persona its own report title, add an at-a-glance tile section to the three operational reports, and make the Spanish report's tile labels, state words and coverage line actually translate.

**Architecture:** `GATHER_MAP`'s keys become stable snake_case **identifiers**; `i18n` gains a tolerant group/state lookup; `builder` translates identifiers at render time (English values equal today's strings, so EN goldens stay frozen). `MetricCard` gains `state_label` (translated display text, keeping `state` as the CSS-class identifier) and `severity_counts` (structured breakdown the builder renders + translates).

**Tech Stack:** Python 3.11+, the existing `core/f0_sectools_core/reports/` engine, pytest.

## Global Constraints

From `docs/superpowers/specs/2026-07-25-report-titles-tiles-i18n-design.md` and CLAUDE.md. Every task's requirements implicitly include this section.

- **EN output must be byte-identical except where a task's own deliverable changes it.** Every new EN i18n value equals the string that renders today (e.g. `group_config_hardening` = `"Config hardening"`), so no *incidental* drift is acceptable. Exactly two intentional golden changes are expected across this plan, each re-frozen in the task that causes it, after reading the diff to confirm nothing else moved:
  - **Task 1** — `golden_detection_en.md` title line: `# Security Operations Report` → `# Detection Coverage Report` (that persona now has its own title). `golden_ciso_en.md` must stay byte-identical here.
  - **Task 2** — `golden_ciso_en.md` state word: `(needs-work)` → `(needs work)` (emit now renders the display word instead of the raw id).
  Any other golden difference means something unintended moved: STOP and report.
- **Translation is tolerant** — an unknown group/state identifier passes through unchanged and never raises. The golden tests build `ScopeMeta` by hand with English labels; that must keep working.
- **CSS classes derive from the state IDENTIFIER, never the translated text** — otherwise Spanish reports lose their colours.
- **i18n EN/ES key parity** is enforced by an existing test; every new key needs both languages.
- **`core/f0_sectools_core/reports/` stays PLATFORM-FREE + MODEL-FREE**; all platform wiring stays in `scripts/`.
- **Redaction unchanged** — every emitted string still goes through `_r`/`_e`.
- **An empty group renders `clear` in muted grey, never green** — "0 detections" is not good news on a dormant fleet.
- **`_degraded`'s title must keep the `not configured` marker** (`sections.DEGRADATION_MARKERS`) or dark groups get misclassified.
- **NO real tenant identifiers** in tests/fixtures. `scripts/` is mypy-exempt; `core/` + servers stay mypy-strict clean; ruff clean.
- **Commit style:** conventional commits, stage specific files (never `git add -A`), each message ending with:
  ```
  Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
  ```
  Use `git commit -F` when the body has backticks. **Do not push.**

## Reference: current code

- `core/f0_sectools_core/reports/i18n.py` — `LABELS: dict[str, dict[str, str]]` (en/es) + `label(lang, key)` which raises `KeyError` on an unknown key. Already contains **unused** `state_strong`/`state_needs_work`/`state_exposure`/`state_not_assessed` keys and `report_title_executive`/`report_title_operational`.
- `core/f0_sectools_core/reports/builder.py` —
  - `_title(lang, tier)` → picks `report_title_executive` if `tier == "executive"` else `report_title_operational`.
  - `_coverage_items(lang, meta)` → `f"{label(lang,'assessed')}: {', '.join(meta.assessed)}"` (and `not_assessed`).
  - `build_report`'s `metric_grid` branch → `metrics = list(scope_meta.pillar_metrics)` then `Section(spec.kind, title, spec.tier, metrics=metrics)`.
  - `build_report(persona, language, narrative, findings, scope_meta)`; `persona` is normalized (hyphen→underscore) at the top via `_normalize_persona`.
- `core/f0_sectools_core/reports/emit.py` — `_metric_card` builds `state = _e(m.state).replace(" ", "-")` for the CSS class and renders `_e(m.state)` as the visible word; `_md_metric` renders `({_r(m.state)})`.
- `core/f0_sectools_core/reports/content.py` — `MetricCard(label, value, state, detail="")`, frozen dataclass.
- `scripts/report_gather.py` — `GATHER_MAP: dict[persona, dict[label, factory]]` with English display labels as keys; `_metric_from(group, findings)` (CISO headline tiles); `_degraded(group, detail)` builds `f"{group} not configured — not assessed"`; `gather` appends `group` to `assessed`/`not_assessed` and (CISO only) `metrics`.

---

### Task 1: i18n foundation + per-persona titles

**Files:**
- Modify: `core/f0_sectools_core/reports/i18n.py`
- Modify: `core/f0_sectools_core/reports/builder.py` (`_title` only)
- Test: `core/tests/test_reports_i18n.py`, `core/tests/test_reports_builder.py`

**Interfaces produced (used by Tasks 2–3):**
- `group_label(lang: str, group_id: str) -> str` — tolerant: returns the translation of `group_<group_id>` or `group_id` unchanged.
- `state_label(lang: str, state_id: str) -> str` — tolerant: returns the translation of `state_<state_id.replace("-", "_")>` or `state_id` unchanged.
- `_title(lang: str, persona: str) -> str` in builder — keys off `report_title_<persona>`.

- [ ] **Step 1: Write the failing tests**

Append to `core/tests/test_reports_i18n.py`:

```python
def test_per_persona_title_keys_exist_in_both_languages():
    from f0_sectools_core.reports.i18n import LABELS

    for persona in ("ciso", "detection_engineer", "threat_hunter", "security_engineer"):
        for lang in ("en", "es"):
            assert LABELS[lang][f"report_title_{persona}"].strip()
    # the CISO title text is unchanged so the frozen golden still matches
    assert LABELS["en"]["report_title_ciso"] == "Executive Risk Briefing"


def test_group_label_translates_known_and_passes_through_unknown():
    from f0_sectools_core.reports.i18n import group_label

    assert group_label("en", "config_hardening") == "Config hardening"
    assert group_label("es", "config_hardening") == "Endurecimiento de configuración"
    assert group_label("en", "weak_techniques") == "Weak techniques"
    # tolerant: an unknown id (or an already-display label) passes through
    assert group_label("es", "Something Custom") == "Something Custom"


def test_state_label_translates_known_and_passes_through_unknown():
    from f0_sectools_core.reports.i18n import state_label

    assert state_label("en", "needs-work") == "needs work"
    assert state_label("es", "needs-work") == "requiere atención"
    assert state_label("en", "clear") == "clear"
    assert state_label("es", "clear") == "sin novedad"
    assert state_label("es", "bogus-state") == "bogus-state"
```

Append to `core/tests/test_reports_builder.py`:

```python
def test_each_persona_gets_its_own_title():
    narrative = "## Executive Summary\nHi.\n"
    titles = {
        p: build_report(p, "en", narrative, [], _scope()).markdown.splitlines()[0]
        for p in ("ciso", "detection-engineer", "threat-hunter", "security-engineer")
    }
    assert titles["ciso"] == "# Executive Risk Briefing"
    assert titles["detection-engineer"] == "# Detection Coverage Report"
    assert titles["threat-hunter"] == "# Threat Hunting Report"
    assert titles["security-engineer"] == "# Security Hardening Report"
    assert len(set(titles.values())) == 4  # all distinct
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest core/tests/test_reports_i18n.py core/tests/test_reports_builder.py -q`
Expected: FAIL — `group_label` doesn't exist; `report_title_ciso` missing; the three operational titles are all "Security Operations Report".

- [ ] **Step 3: Add the new i18n keys**

In `core/f0_sectools_core/reports/i18n.py`, inside the `"en"` table **replace**
`"report_title_executive"` and `"report_title_operational"` with the four
per-persona titles, and add the group/state/detail keys:

```python
        "report_title_ciso": "Executive Risk Briefing",
        "report_title_detection_engineer": "Detection Coverage Report",
        "report_title_threat_hunter": "Threat Hunting Report",
        "report_title_security_engineer": "Security Hardening Report",
```

and add (still in `"en"`):

```python
        # Gather-group display names. EN values MUST equal the labels that render
        # today, so English output (and the frozen goldens) stay byte-identical.
        "group_config_hardening": "Config hardening",
        "group_attack_validation": "Attack validation",
        "group_vulnerability_exposure": "Vulnerability exposure",
        "group_device_compliance": "Device compliance",
        "group_data_risk": "Data risk",
        "group_endpoint_coverage": "Endpoint coverage",
        "group_alerts_mitre": "Alerts (MITRE)",
        "group_incidents": "Incidents",
        "group_detection_rules": "Detection rules",
        "group_endpoint_detections": "Endpoint detections",
        "group_weak_techniques": "Weak techniques",
        "group_conditional_access": "Conditional access",
        "group_privileged_roles": "Privileged roles",
        "group_risky_users": "Risky users",
        "group_stale_devices": "Stale devices",
        "group_top_vulnerabilities": "Top vulnerabilities",
        "state_clear": "clear",
        "nothing_in_window": "nothing in this window",
        "sev_critical": "critical",
        "sev_high": "high",
        "sev_medium": "medium",
        "sev_low": "low",
        "sev_info": "info",
```

Mirror all of it in the `"es"` table:

```python
        "report_title_ciso": "Informe Ejecutivo de Riesgo",
        "report_title_detection_engineer": "Informe de Cobertura de Detección",
        "report_title_threat_hunter": "Informe de Caza de Amenazas",
        "report_title_security_engineer": "Informe de Endurecimiento de Seguridad",
        ...
        "group_config_hardening": "Endurecimiento de configuración",
        "group_attack_validation": "Validación de ataques",
        "group_vulnerability_exposure": "Exposición a vulnerabilidades",
        "group_device_compliance": "Cumplimiento de dispositivos",
        "group_data_risk": "Riesgo de datos",
        "group_endpoint_coverage": "Cobertura de endpoints",
        "group_alerts_mitre": "Alertas (MITRE)",
        "group_incidents": "Incidentes",
        "group_detection_rules": "Reglas de detección",
        "group_endpoint_detections": "Detecciones de endpoint",
        "group_weak_techniques": "Técnicas débiles",
        "group_conditional_access": "Acceso condicional",
        "group_privileged_roles": "Roles privilegiados",
        "group_risky_users": "Usuarios de riesgo",
        "group_stale_devices": "Dispositivos obsoletos",
        "group_top_vulnerabilities": "Vulnerabilidades principales",
        "state_clear": "sin novedad",
        "nothing_in_window": "sin novedad en esta ventana",
        "sev_critical": "crítico",
        "sev_high": "alto",
        "sev_medium": "medio",
        "sev_low": "bajo",
        "sev_info": "informativo",
```

Note the existing ES `state_needs_work` is `"requiere atención"` — leave the four
existing `state_*` values as they are; they finally get consumed in Task 2.

- [ ] **Step 4: Add the tolerant lookups**

Append to `core/f0_sectools_core/reports/i18n.py`:

```python
def _lookup(lang: str, key: str, fallback: str) -> str:
    """Translate a key, falling back to the raw value.

    Group and state identifiers come from the gather layer, which is free to add
    a group before a translation exists. A missing translation must degrade to
    the identifier, never raise at render time.
    """
    try:
        return LABELS[lang][key]
    except KeyError:
        return fallback


def group_label(lang: str, group_id: str) -> str:
    """Display name for a gather-group identifier (tolerant of unknown ids)."""
    return _lookup(lang, f"group_{group_id}", group_id)


def state_label(lang: str, state_id: str) -> str:
    """Display word for a metric state identifier (tolerant of unknown ids)."""
    return _lookup(lang, f"state_{state_id.replace('-', '_')}", state_id)
```

- [ ] **Step 5: Key the title off the persona**

In `core/f0_sectools_core/reports/builder.py` replace `_title` and its call site:

```python
def _title(lang: str, persona: str) -> str:
    return label(lang, f"report_title_{persona}")
```

Find the call `_title(language, tier)` inside `build_report` and change it to
`_title(language, persona)` (persona is already normalized to underscores at the
top of `build_report`). If `tier` becomes unused as a result, leave it — it is
still used for `ReportContent.tier` and the section tiers.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest core/tests/test_reports_i18n.py core/tests/test_reports_builder.py -v`
Expected: PASS, including the pre-existing key-parity test.

- [ ] **Step 7: Verify goldens + suite + types**

Run:
```bash
uv run pytest -q
uv run mypy core/ servers/
uv run ruff check .
git diff --stat core/tests/fixtures/reports/
```
Expected: all green and the last command prints **nothing** (goldens untouched — the CISO title string is unchanged).

- [ ] **Step 8: Commit**

```bash
git add core/f0_sectools_core/reports/i18n.py core/f0_sectools_core/reports/builder.py \
  core/tests/test_reports_i18n.py core/tests/test_reports_builder.py
git commit -m "feat(reports): per-persona titles + tolerant group/state i18n lookups"
# (append the two trailers)
```

---

### Task 2: Translate the tile chrome and coverage line

**Files:**
- Modify: `core/f0_sectools_core/reports/content.py` (`MetricCard.state_label`, `severity_counts`)
- Modify: `core/f0_sectools_core/reports/builder.py` (translate metrics + coverage)
- Modify: `core/f0_sectools_core/reports/emit.py` (render `state_label`)
- Test: `core/tests/test_reports_builder.py`, `core/tests/test_reports_emit.py`

**Interfaces:**
- Consumes: `i18n.group_label`, `i18n.state_label` (Task 1).
- Produces: `MetricCard(label, value, state, detail="", state_label="", severity_counts=())` where `severity_counts: tuple[tuple[str, int], ...]` is an ordered severity→count breakdown (used by Task 3's operational tiles).

- [ ] **Step 1: Write the failing tests**

Append to `core/tests/test_reports_builder.py`:

```python
def test_spanish_report_translates_tiles_and_coverage():
    from f0_sectools_core.reports.content import MetricCard, ScopeMeta

    meta = ScopeMeta(
        generated_at="2026-07-24 14:22", tenant_label="Contoso",
        window_label="Trailing 7 days", platforms_queried=["defender"],
        findings_count=1, assessed=["config_hardening"], not_assessed=["data_risk"],
        pillar_metrics=[MetricCard("config_hardening", "90%", "needs-work",
                                   detail="Microsoft Secure Score")],
    )
    md = build_report("ciso", "es", "## Resumen Ejecutivo\nHola.\n", [], meta).markdown
    # group ids and state words render in Spanish
    assert "Endurecimiento de configuración" in md
    assert "requiere atención" in md
    assert "Riesgo de datos" in md            # the not-assessed coverage entry
    # ...and the raw identifiers never leak
    assert "config_hardening" not in md
    assert "needs-work" not in md


def test_english_report_renders_group_ids_as_todays_labels():
    from f0_sectools_core.reports.content import MetricCard, ScopeMeta

    meta = ScopeMeta(
        generated_at="2026-07-24 14:22", tenant_label="Contoso",
        window_label="Trailing 7 days", platforms_queried=["defender"],
        findings_count=1, assessed=["config_hardening"], not_assessed=[],
        pillar_metrics=[MetricCard("config_hardening", "90%", "needs-work")],
    )
    md = build_report("ciso", "en", "## Executive Summary\nHi.\n", [], meta).markdown
    assert "Config hardening" in md          # identical to today's output
    assert "needs work" in md
```

Append to `core/tests/test_reports_emit.py`:

```python
def test_css_class_uses_state_id_even_when_display_text_is_translated():
    from f0_sectools_core.reports.content import (
        BlockKind, MetricCard, ReportContent, Section,
    )
    from f0_sectools_core.reports.emit import to_html

    card = MetricCard("Cumplimiento", "67%", "needs-work",
                      state_label="requiere atención")
    content = ReportContent(
        persona="ciso", language="es", tier="executive",
        title="Informe", subtitle="sub",
        sections=[Section(BlockKind.metric_grid, "Postura", "executive", metrics=[card])],
    )
    html = to_html(content)
    assert "metric__state--needs-work" in html      # class from the stable id
    assert "requiere atención" in html              # visible word translated
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest core/tests/test_reports_builder.py core/tests/test_reports_emit.py -q`
Expected: FAIL — `MetricCard` has no `state_label`; the ES report shows raw ids.

- [ ] **Step 3: Extend `MetricCard`**

In `core/f0_sectools_core/reports/content.py`:

```python
@dataclass(frozen=True)
class MetricCard:
    label: str        # gather-group identifier (translated by the builder) or display text
    value: str        # the compact headline number
    state: str        # stable id -> CSS class: strong | needs-work | exposure | not-assessed | clear
    detail: str = ""  # small descriptor line
    state_label: str = ""  # translated state word; emit falls back to `state`
    severity_counts: tuple[tuple[str, int], ...] = ()  # ordered severity -> count breakdown
```

- [ ] **Step 4: Translate in the builder**

In `core/f0_sectools_core/reports/builder.py`, add the imports
`from .i18n import group_label, label, state_label` (keep `label`), and add:

```python
def _localize_metric(lang: str, m: MetricCard) -> MetricCard:
    """Render a gather-produced card in the report's language.

    `label`/`state` arrive as identifiers from the gather layer; translate them
    for display while keeping `state` itself stable (emit derives the CSS class
    from it). `severity_counts`, when present, becomes the translated detail line.
    """
    detail = m.detail
    if m.severity_counts:
        detail = " · ".join(
            f"{count} {label(lang, f'sev_{sev}')}" for sev, count in m.severity_counts
        )
    elif detail:
        detail = _lookup_or_raw(lang, detail)
    return MetricCard(
        label=group_label(lang, m.label),
        value=m.value,
        state=m.state,
        detail=detail,
        state_label=state_label(lang, m.state),
        severity_counts=m.severity_counts,
    )


def _lookup_or_raw(lang: str, text: str) -> str:
    """Translate a detail that is exactly an i18n key; otherwise pass it through.

    Exact-match only — a CISO tile's detail is a finding title and must never be
    partially rewritten.
    """
    try:
        return label(lang, text)
    except KeyError:
        return text
```

Change the `metric_grid` branch of `build_report` to localize:

```python
        elif spec.kind is BlockKind.metric_grid:
            metrics = [_localize_metric(language, m) for m in scope_meta.pillar_metrics]
            sections.append(Section(spec.kind, title, spec.tier, metrics=metrics))
```

Translate the coverage entries too:

```python
def _coverage_items(lang: str, meta: ScopeMeta) -> list[str]:
    items: list[str] = []
    if meta.assessed:
        names = ", ".join(group_label(lang, g) for g in meta.assessed)
        items.append(f"{label(lang, 'assessed')}: {names}")
    if meta.not_assessed:
        names = ", ".join(group_label(lang, g) for g in meta.not_assessed)
        items.append(f"{label(lang, 'not_assessed')}: {names}")
    return items
```

- [ ] **Step 5: Render the translated state in emit**

In `core/f0_sectools_core/reports/emit.py`:

- `_md_metric`: change the state to the display word —
  ```python
  line = f"- {head} — {_r(m.label)} ({_r(m.state_label or m.state)})"
  ```
- `_metric_card`: keep the class from `m.state`, render the display word:
  ```python
      state = _e(m.state).replace(" ", "-")
      ...
      f'<div class="metric__state metric__state--{state}">{_e(m.state_label or m.state)}</div>'
  ```

- [ ] **Step 6: Run tests + confirm goldens frozen**

Run:
```bash
uv run pytest core/tests/test_reports_builder.py core/tests/test_reports_emit.py -v
uv run pytest -q
git diff --stat core/tests/fixtures/reports/
```
**Expected — one intentional golden change.** Today `emit` renders the raw state
id, so the CISO golden reads `(needs-work)`. From now on it renders the EN
display word from `state_needs_work`, which is `"needs work"` (a space). That is
a deliberate typographic improvement for a human-facing report, so **re-freeze
`golden_ciso_en.md` here** — then READ the diff and confirm the ONLY change is
state words losing their hyphen (`(needs-work)` → `(needs work)`). If anything
else differs — a label, a number, a section, the title — STOP and report
NEEDS_CONTEXT with the diff.

`golden_detection_en.md` must NOT change in this task (it has no metric tiles yet).

- [ ] **Step 7: Types + lint, then commit**

```bash
uv run mypy core/ servers/
uv run ruff check .
git add core/f0_sectools_core/reports/content.py core/f0_sectools_core/reports/builder.py \
  core/f0_sectools_core/reports/emit.py core/tests/test_reports_builder.py \
  core/tests/test_reports_emit.py core/tests/fixtures/reports/golden_ciso_en.md
git commit -m "feat(reports): translate tile labels, state words and the coverage line"
# (append the two trailers)
```

---

### Task 3: Operational at-a-glance tiles + group identifiers

**Files:**
- Modify: `scripts/report_gather.py` (GATHER_MAP keys → ids, count tiles, humanized `_degraded`)
- Modify: `core/f0_sectools_core/reports/sections.py` (metric_grid for operational personas)
- Modify: `core/f0_sectools_core/reports/assets/report.css` (`.metric__state--clear`)
- Test: `scripts/tests/test_gen_report.py`, `core/tests/test_reports_sections.py`

**Interfaces:**
- Consumes: `MetricCard(..., severity_counts=...)` (Task 2), `i18n` group ids (Task 1).
- Produces: `GATHER_MAP` keyed by group identifiers; `_count_metric(group, findings) -> MetricCard`.

- [ ] **Step 1: Write the failing tests**

Append to `scripts/tests/test_gen_report.py`:

```python
def test_gather_map_uses_stable_identifiers():
    # keys are snake_case ids the i18n layer translates, not display labels
    for persona, groups in report_gather.GATHER_MAP.items():
        for gid in groups:
            assert gid == gid.lower(), (persona, gid)
            assert " " not in gid, (persona, gid)
    assert "config_hardening" in report_gather.GATHER_MAP["ciso"]
    assert "weak_techniques" in report_gather.GATHER_MAP["detection_engineer"]


def test_operational_persona_gets_count_tiles(monkeypatch):
    from f0_sectools_core.schema.findings import Finding, FindingType, Severity

    async def three(window_hours):
        return [
            Finding(source="projectachilles", finding_type=FindingType.risk,
                    severity=Severity.high, title="Weak coverage: T1059"),
            Finding(source="projectachilles", finding_type=FindingType.risk,
                    severity=Severity.high, title="Weak coverage: T1078"),
            Finding(source="projectachilles", finding_type=FindingType.risk,
                    severity=Severity.medium, title="Weak coverage: T1005"),
        ]

    async def empty(window_hours):
        return []

    monkeypatch.setitem(report_gather.GATHER_MAP, "detection_engineer",
                        {"weak_techniques": three, "incidents": empty})
    _findings, meta = asyncio.run(report_gather.gather("detection-engineer", 168))
    tiles = {m.label: m for m in meta.pillar_metrics}
    assert tiles["weak_techniques"].value == "3"
    assert tiles["weak_techniques"].state == "needs-work"        # worst severity is high
    assert tiles["weak_techniques"].severity_counts == (("high", 2), ("medium", 1))
    # an empty group is CLEAR (muted), never green/"strong"
    assert tiles["incidents"].value == "0"
    assert tiles["incidents"].state == "clear"
    assert tiles["incidents"].detail == "nothing_in_window"


def test_count_tile_state_escalates_to_exposure_on_critical(monkeypatch):
    from f0_sectools_core.schema.findings import Finding, FindingType, Severity

    async def crit(window_hours):
        return [Finding(source="tenable", finding_type=FindingType.risk,
                        severity=Severity.critical, title="RCE")]

    monkeypatch.setitem(report_gather.GATHER_MAP, "security_engineer", {"top_vulnerabilities": crit})
    _f, meta = asyncio.run(report_gather.gather("security-engineer", 168))
    assert meta.pillar_metrics[0].state == "exposure"
```

Append to `core/tests/test_reports_sections.py`:

```python
def test_operational_personas_have_an_at_a_glance_section():
    for persona in ("detection_engineer", "threat_hunter", "security_engineer"):
        kinds = [s.kind for s in SECTION_MAPS[persona]]
        assert BlockKind.metric_grid in kinds, persona
        # it sits directly after the narrative, like the CISO's
        assert kinds.index(BlockKind.metric_grid) == kinds.index(BlockKind.narrative) + 1
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest scripts/tests/test_gen_report.py core/tests/test_reports_sections.py -q`
Expected: FAIL — GATHER_MAP keys are display labels; no count tiles; operational maps have no `metric_grid`.

- [ ] **Step 3: Re-key `GATHER_MAP` to identifiers**

In `scripts/report_gather.py`, rewrite the dict's keys (factories unchanged):

```python
GATHER_MAP: dict[str, dict[str, Callable[[int], Awaitable[list[Finding]]]]] = {
    "ciso": {
        "config_hardening": _pillar_config_hardening,
        "attack_validation": _pillar_attack_validation,
        "vulnerability_exposure": _pillar_vuln_exposure,
        "device_compliance": _pillar_device_compliance,
        "data_risk": _pillar_data_risk,
        "endpoint_coverage": _pillar_endpoint_coverage,
    },
    "detection_engineer": {
        "alerts_mitre": _defender_alerts,
        "incidents": _defender_incidents,
        "detection_rules": _lc_dr_rules,
        "endpoint_detections": _lc_detections,
        "weak_techniques": _pa_weak_techniques,
    },
    "threat_hunter": {
        "incidents": _defender_incidents,
        "alerts_mitre": _defender_alerts,
        "endpoint_detections": _lc_detections,
        "endpoint_coverage": _pillar_endpoint_coverage,
    },
    "security_engineer": {
        "config_hardening": _pillar_config_hardening,
        "conditional_access": _entra_conditional_access,
        "privileged_roles": _entra_privileged_roles,
        "risky_users": _entra_risky_users,
        "device_compliance": _pillar_device_compliance,
        "stale_devices": _intune_stale_devices,
        "vulnerability_exposure": _pillar_vuln_exposure,
        "top_vulnerabilities": _tenable_top_vulns,
    },
}
```

- [ ] **Step 4: Humanize the degraded title**

Group ids would make the degradation title read "config_hardening not configured".
In `_degraded`, humanize while keeping the marker:

```python
def _degraded(group: str, detail: str) -> Finding:
    human = group.replace("_", " ").capitalize()
    return Finding(
        source=group,
        finding_type=FindingType.posture,
        severity=Severity.info,
        # "not configured" is the marker sections.is_not_assessed matches — keep it.
        title=f"{human} not configured — not assessed",
        evidence=[Evidence(key="reason", value=redact_text(detail)[:300])],
    )
```

- [ ] **Step 5: Add the count-tile builder**

Add to `scripts/report_gather.py` (near `_metric_from`):

```python
_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_STATE = {
    "critical": "exposure", "high": "needs-work", "medium": "needs-work",
    "low": "strong", "info": "strong",
}


def _count_metric(group: str, findings: list[Finding]) -> MetricCard:
    """An at-a-glance tile for an operational group: how many findings it produced.

    An empty group is `clear`, not `strong` — "0 endpoint detections" is not good
    news when most sensors are dormant, and a green tile would contradict the
    narrative. A group whose findings are all degradations is `not-assessed`.
    """
    real = [f for f in findings if not is_not_assessed(f)]
    if not findings:
        return MetricCard(group, "0", "clear", detail="nothing_in_window")
    if not real:
        return MetricCard(group, "—", "not-assessed")
    counts = {sev: sum(1 for f in real if f.severity.value == sev) for sev in _SEV_ORDER}
    worst = next((s for s in _SEV_ORDER if counts[s]), "info")
    breakdown = tuple((s, counts[s]) for s in _SEV_ORDER if counts[s])
    return MetricCard(group, str(len(real)), _SEV_STATE[worst], severity_counts=breakdown)
```

- [ ] **Step 6: Build tiles for every persona**

In `gather`, replace the CISO-only metric block:

```python
        # CISO groups are one headline posture finding each (a percentage/score);
        # operational groups are lists, so their tile is the count.
        if key == "ciso":
            metrics.append(_metric_from(group, group_findings))
        else:
            metrics.append(_count_metric(group, group_findings))
```

- [ ] **Step 7: Give operational personas a metric_grid section**

In `core/f0_sectools_core/reports/sections.py`, insert a `metric_grid` spec
directly after the narrative for the three operational personas, e.g.:

```python
    "detection_engineer": [
        SectionSpec(BlockKind.narrative, "sec_executive_summary", _OPS),
        SectionSpec(BlockKind.metric_grid, "sec_posture", _OPS, FindingGroup.posture),
        SectionSpec(BlockKind.finding_table, "sec_findings", _OPS, FindingGroup.all),
        SectionSpec(BlockKind.coverage, "sec_scope", _OPS),
        SectionSpec(BlockKind.open_questions, "sec_open_questions", _OPS),
        SectionSpec(BlockKind.provenance, "sec_provenance", _OPS),
    ],
```

Do the same for `threat_hunter` and `security_engineer`.

- [ ] **Step 8: Add the `clear` state CSS**

In `core/f0_sectools_core/reports/assets/report.css`, next to the other state
rules:

```css
.metric__state--clear { color:var(--muted); }
```

- [ ] **Step 9: Run everything**

Run:
```bash
uv run pytest scripts/tests/test_gen_report.py core/tests/test_reports_sections.py -v
uv run pytest -q
uv run mypy core/ servers/
uv run ruff check .
git diff --stat core/tests/fixtures/reports/
```
Expected: all green. **The goldens must be untouched** — they build `ScopeMeta`
by hand and never call `gather`, and the detection golden's section list gains a
`metric_grid` whose metrics list is empty (its hand-built `ScopeMeta` has no
`pillar_metrics`), which renders as an empty section body. If `golden_detection_en.md`
changes because of that empty section, re-freeze it, READ it, and confirm the only
change is the new (empty) "Posture at a glance" heading; anything else → STOP.

- [ ] **Step 10: Commit**

```bash
git add scripts/report_gather.py core/f0_sectools_core/reports/sections.py \
  core/f0_sectools_core/reports/assets/report.css \
  scripts/tests/test_gen_report.py core/tests/test_reports_sections.py
# plus core/tests/fixtures/reports/golden_detection_en.md only if Step 9 legitimately re-froze it
git commit -m "feat(reports): at-a-glance count tiles for operational personas"
# (append the two trailers)
```

---

## Post-implementation (operator-gated, not a task)

Regenerate the four EN reports plus a Spanish one and eyeball: distinct titles,
operational tiles with counts and a muted `clear` state for empty groups, and
Spanish tile labels / state words / coverage line.

## Self-review (author)

- **Spec coverage:** per-persona titles (T1) ✅ · tolerant group/state lookups (T1) ✅ · `MetricCard.state_label` + `severity_counts` (T2) ✅ · builder translation of tiles + coverage (T2) ✅ · emit renders display text while the CSS class stays id-driven (T2) ✅ · group identifiers (T3) ✅ · count tiles incl. `clear` for empty (T3) ✅ · operational `metric_grid` section (T3) ✅ · `clear` CSS (T3) ✅ · humanized degraded title keeping the marker (T3) ✅.
- **Placeholder scan:** none — every step carries exact code or commands.
- **Type consistency:** `MetricCard(label, value, state, detail, state_label, severity_counts)` used identically in `_count_metric`, `_metric_from`, `_localize_metric` and both emitters; `group_label`/`state_label` signatures match their call sites; `_title(lang, persona)` matches its single call site.

## Out of scope

Translating narrative prose or degraded-finding titles; charts/gauges; new gather groups or tools.
