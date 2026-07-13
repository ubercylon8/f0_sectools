"""Tenable Vulnerability Management read tools -> findings.

Read-only. Each tool catches a TenableError (auth / permission / rate-limit /
gateway) and returns a graceful finding instead of crashing. Response field
names are validated by the live smoke test (recipe step 9).
"""
from __future__ import annotations

import re
from typing import Any

from f0_sectools_core.schema.findings import (
    Severity,
)

# Tenable severity integer 0-4 -> our Severity.
_SEV_BY_INT = {
    0: Severity.info,
    1: Severity.low,
    2: Severity.medium,
    3: Severity.high,
    4: Severity.critical,
}
# severity_min enum string -> the minimum Tenable integer to include.
_SEV_MIN = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _sev(value: Any) -> Severity:
    """Tenable severity (int 0-4, or a name) -> Severity; unknown -> info."""
    if isinstance(value, int):
        return _SEV_BY_INT.get(value, Severity.info)
    return {s.value: s for s in Severity}.get(str(value).lower(), Severity.info)


def _rows(resp: Any, key: str) -> list[dict[str, Any]]:
    """Extract a list of rows: a bare array, or ``{key: [...]}``."""
    if isinstance(resp, list):
        return resp
    if isinstance(resp, dict):
        got = resp.get(key)
        if isinstance(got, list):
            return got
    return []
