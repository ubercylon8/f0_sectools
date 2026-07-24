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
