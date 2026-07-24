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
