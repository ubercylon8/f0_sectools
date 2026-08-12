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
        "report_title_ciso": "Executive Risk Briefing",
        "report_title_detection_engineer": "Detection Coverage Report",
        "report_title_threat_hunter": "Threat Hunting Report",
        "report_title_security_engineer": "Security Hardening Report",
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
        # Gather-group display names. EN values MUST equal the labels that render
        # today, so English output (and the frozen goldens) stay byte-identical.
        "group_config_hardening": "Config hardening",
        "group_attack_validation": "Attack validation",
        "group_vulnerability_exposure": "Vulnerability exposure",
        "group_device_compliance": "Device compliance",
        "group_data_risk": "Data risk",
        "group_endpoint_coverage": "Endpoint coverage",
        "group_detection_coverage": "Detection coverage",
        "group_alerts_mitre": "Alerts (MITRE)",
        "group_incidents": "Incidents",
        "group_detection_rules": "Detection rules",
        "group_endpoint_detections": "Endpoint detections",
        "group_weak_techniques": "Weak techniques",
        "group_analytics_rules": "Analytics rules",
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
    },
    "es": {
        "report_title_ciso": "Informe Ejecutivo de Riesgo",
        "report_title_detection_engineer": "Informe de Cobertura de Detección",
        "report_title_threat_hunter": "Informe de Caza de Amenazas",
        "report_title_security_engineer": "Informe de Endurecimiento de Seguridad",
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
        "group_config_hardening": "Endurecimiento de configuración",
        "group_attack_validation": "Validación de ataques",
        "group_vulnerability_exposure": "Exposición a vulnerabilidades",
        "group_device_compliance": "Cumplimiento de dispositivos",
        "group_data_risk": "Riesgo de datos",
        "group_endpoint_coverage": "Cobertura de endpoints",
        "group_detection_coverage": "Cobertura de detección",
        "group_alerts_mitre": "Alertas (MITRE)",
        "group_incidents": "Incidentes",
        "group_detection_rules": "Reglas de detección",
        "group_endpoint_detections": "Detecciones de endpoint",
        "group_weak_techniques": "Técnicas débiles",
        "group_analytics_rules": "Reglas analíticas",
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
    },
}


def label(lang: str, key: str) -> str:
    """Return the label for a language/key. Raises KeyError if either is unknown."""
    return LABELS[lang][key]


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


def sev_label(lang: str, sev_id: str) -> str:
    """Display word for a severity token (tolerant of unknown tokens)."""
    return _lookup(lang, f"sev_{sev_id}", sev_id)
