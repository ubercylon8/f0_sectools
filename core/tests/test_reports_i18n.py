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


def test_sev_label_translates_known_and_passes_through_unknown():
    from f0_sectools_core.reports.i18n import sev_label

    assert sev_label("en", "high") == "high"
    assert sev_label("es", "high") == "alto"
    # tolerant: an unknown severity token must pass through, never raise —
    # the render path (builder._localize_metric) cannot afford a KeyError here.
    assert sev_label("en", "bogus-sev") == "bogus-sev"
    assert sev_label("es", "bogus-sev") == "bogus-sev"
