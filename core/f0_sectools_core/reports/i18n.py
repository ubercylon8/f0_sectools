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
