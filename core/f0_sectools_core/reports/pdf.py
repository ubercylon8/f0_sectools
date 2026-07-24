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
        import weasyprint  # type: ignore[import-untyped]
    except ModuleNotFoundError as e:
        raise ReportsPdfUnavailable(
            "PDF export needs WeasyPrint. Install it with: "
            "pip install 'f0-sectools-core[reports]'"
        ) from e
    result: bytes = weasyprint.HTML(string=html).write_pdf()
    return result
