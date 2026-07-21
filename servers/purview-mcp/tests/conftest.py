"""Test fixtures for the Purview server."""
from __future__ import annotations

import pytest
from f0_purview_mcp import tools


@pytest.fixture(autouse=True)
def _clear_audit_search_cache():
    """search_audit_log dedupes via a module-global cache; clear it around every
    test so shared default filters can't leak state between tests (CC review #63)."""
    tools._RECENT_SEARCHES.clear()
    yield
    tools._RECENT_SEARCHES.clear()
