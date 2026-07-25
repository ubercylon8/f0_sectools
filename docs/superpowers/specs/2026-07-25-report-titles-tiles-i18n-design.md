# Per-Persona Titles, Operational At-a-Glance, and Translated Tile Chrome — Design

**Date:** 2026-07-25 · **Status:** approved-pending-review · **Branch:** `feat/report-persona-gathering`

Three related report fixes, all in the tile/chrome layer:

1. **Per-persona titles** — the three operational reports all say "Security Operations Report".
2. **An at-a-glance section for operational reports** — today only the CISO gets one.
3. **Translated tile chrome** — the Spanish report renders group labels and state
   words in English, because they are display strings minted in the gather layer
   rather than i18n keys.

## Problems

**Titles are keyed off tier, not persona.** `builder._title(lang, tier)` picks
`report_title_executive` or `report_title_operational`, so detection-engineer,
threat-hunter and security-engineer are all titled "Security Operations Report";
only the subtitle differentiates them.

**No at-a-glance for operational personas.** `SECTION_MAPS` gives `metric_grid`
to the CISO only. That was right when operational personas had no headline
number, but each gather group now has an obvious one: how many findings it
produced.

**The Spanish report is half-translated.** Verified in a real ES report:

```
- **90%** — Config hardening (strong) · Microsoft Secure Score: …
Evaluado: Config hardening, Attack validation, …
```

Narrative and section headings translate; tiles and the coverage line do not.
Root cause: `GATHER_MAP` keys are English display labels that flow untouched into
`MetricCard.label`, `ScopeMeta.assessed/not_assessed`, and the rendered output.
The `state_*` keys already in `i18n.py` are **defined but never consumed** —
`emit._metric_card` renders `m.state` raw.

## Design

### 1. Per-persona titles

Replace `_title(lang, tier)` with `_title(lang, persona)` and key off the
persona. Four keys replace the two tier keys:

| Persona | EN | ES |
|---|---|---|
| `ciso` | Executive Risk Briefing | Informe Ejecutivo de Riesgo |
| `detection_engineer` | Detection Coverage Report | Informe de Cobertura de Detección |
| `threat_hunter` | Threat Hunting Report | Informe de Caza de Amenazas |
| `security_engineer` | Security Hardening Report | Informe de Endurecimiento de Seguridad |

The CISO string is unchanged, so `golden_ciso_en.md` stays frozen.

### 2. Group identifiers + translated chrome

`GATHER_MAP`'s keys become **stable snake_case identifiers** (`config_hardening`,
`alerts_mitre`, `weak_techniques`, …) instead of display labels. They flow
through `MetricCard.label` and `ScopeMeta.assessed/not_assessed` as identifiers,
and `builder` translates them at render time via a new i18n group table.

Translation is **tolerant**: an unknown identifier passes through unchanged. This
keeps hand-built `ScopeMeta` fixtures (the golden tests construct one directly
with English labels) working, and means a future group without a translation
degrades to its raw label rather than raising.

```python
# core/f0_sectools_core/reports/i18n.py
def group_label(lang: str, group_id: str) -> str:   # tolerant lookup
def state_label(lang: str, state_id: str) -> str:   # tolerant lookup
```

New group keys (the union across personas, 16): `group_config_hardening`,
`group_attack_validation`, `group_vulnerability_exposure`,
`group_device_compliance`, `group_data_risk`, `group_endpoint_coverage`,
`group_alerts_mitre`, `group_incidents`, `group_detection_rules`,
`group_endpoint_detections`, `group_weak_techniques`,
`group_conditional_access`, `group_privileged_roles`, `group_risky_users`,
`group_stale_devices`, `group_top_vulnerabilities`.

Their **EN values are exactly today's display labels** (`group_config_hardening`
= "Config hardening"), so English output — including the frozen CISO golden — is
byte-identical.

### 3. State identifier vs. state display text

`emit._metric_card` builds a CSS class from the state
(`metric__state--{state}`), so the state cannot simply become translated text or
the class breaks in Spanish. Separate the two:

```python
@dataclass(frozen=True)
class MetricCard:
    label: str
    value: str
    state: str                 # stable id -> CSS class (strong | needs-work | exposure | not-assessed | clear)
    detail: str = ""
    state_label: str = ""      # translated display text; falls back to `state`
```

`emit` uses `m.state` for the class and `m.state_label or m.state` for the
visible word. `builder` fills `state_label` (and the translated `label`) when it
assembles the metric section. The existing `state_*` i18n keys finally get
consumed; `state_clear` is added.

### 4. Operational at-a-glance tiles

Add a `metric_grid` section to the three operational `SECTION_MAPS`, placed
directly after the narrative (same position as the CISO's). `gather` builds one
tile per group for operational personas:

- **value** — the number of findings the group returned (`"10"`, `"0"`).
- **label** — the group identifier (translated by the builder).
- **state** — the group's worst severity: `critical` → `exposure`; `high`/`medium`
  → `needs-work`; `low`/`info` → `strong`; **empty group → `clear`**.
- **detail** — a severity breakdown (`"9 high · 1 medium"`), or the i18n
  `nothing_in_window` string when the group is empty.

**An empty group is `clear`, styled muted grey — never green.** On a
threat-hunter report "0 endpoint detections" is not good news when 94% of sensors
are dormant; a green tile would contradict the narrative. `clear` states the
fact without claiming it is good.

The CISO's tiles keep their existing headline-based behaviour unchanged.

New i18n keys for the tile detail: `state_clear`, `nothing_in_window`, and
severity words `sev_critical`, `sev_high`, `sev_medium`, `sev_low`, `sev_info`
(so the ES breakdown reads "9 alto · 1 medio").

### 5. Degraded-group titles stay human-readable

`_degraded(group, …)` builds its title from the group label. With identifiers it
would read "config_hardening not configured". Humanize it —
`group.replace("_", " ").capitalize()` — so the title stays readable and keeps
the `not configured` marker `is_not_assessed` matches. These findings surface
through the coverage section (translated) rather than as rendered rows, so an
English title here is acceptable; noted as a known limit.

## Components / files

- `core/f0_sectools_core/reports/i18n.py` — 4 title keys (replacing 2), 16 group
  keys, `state_clear`, `nothing_in_window`, 5 severity words; `group_label()` and
  `state_label()` tolerant lookups.
- `core/f0_sectools_core/reports/content.py` — `MetricCard.state_label`.
- `core/f0_sectools_core/reports/builder.py` — `_title(lang, persona)`; translate
  group labels + state words when building the metric section and the coverage
  items.
- `core/f0_sectools_core/reports/emit.py` — render `m.state_label or m.state` as
  the visible state; keep `m.state` for the CSS class.
- `core/f0_sectools_core/reports/sections.py` — `metric_grid` section for the
  three operational personas.
- `core/f0_sectools_core/reports/assets/report.css` — `.metric__state--clear`
  (muted).
- `scripts/report_gather.py` — `GATHER_MAP` keys → identifiers; count-tiles for
  operational personas; humanized `_degraded` title.
- Tests + goldens: EN goldens must stay byte-identical (English strings
  unchanged); add an ES tile/coverage assertion and operational tile tests.

## Error handling & guarantees

- **Tolerant translation** — an unknown group/state identifier renders as-is; no
  lookup can raise at render time.
- **EN output unchanged** — every EN value equals today's display string, so the
  frozen goldens hold. This is the primary regression guard.
- **CSS classes stay stable** — driven by the state identifier, never the
  translated text, so Spanish reports keep their colours.
- **Redaction unchanged** — all tile strings still pass through `_r`/`_e`.
- **i18n key parity** — the existing EN/ES parity test covers every new key.

## Testing

Layer A (offline, CI):
- Titles differ per persona in both languages; CISO title unchanged.
- `group_label`/`state_label` translate known ids and pass unknown ids through.
- Operational personas get a `metric_grid` section; tiles show counts, worst-severity
  state, and `clear` + `nothing_in_window` for an empty group.
- ES report renders translated group labels, state words and coverage line
  (the specific bug: no "Config hardening"/"needs-work" in an ES report).
- CSS class still derives from the state id when the display text is Spanish.
- Both EN goldens byte-identical; i18n key-parity passes.

Layer B (operator-gated): regenerate the four EN reports plus an ES one and
eyeball titles, operational tiles, and Spanish chrome.

## Out of scope

- Translating narrative prose (the agent authors it in the target language).
- Translating degraded-finding titles (see §5).
- Charts/gauges; new gather groups or tools.
