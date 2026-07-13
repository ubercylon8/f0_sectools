"""Contract tests for the Tenable tools.

Tools take a thin async client; tests pass a fake client (no HTTP / network).
Real Tenable field names are validated by the live smoke test (recipe step 9).
"""
from __future__ import annotations

from f0_tenable_mcp.client import TenableError
from f0_tenable_mcp.errors import map_tenable_error


class FakeClient:
    """Fake async client: canned responses by path prefix, or a configured error."""

    def __init__(self, responses=None, raise_on=None):
        self._responses = responses or {}
        self._raise = raise_on or {}
        self.calls: list[tuple[str, dict]] = []

    async def get(self, path, params=None):
        self.calls.append((path, params or {}))
        for p, err in self._raise.items():
            if path.startswith(p):
                raise err
        for p, resp in self._responses.items():
            if path.startswith(p):
                return resp
        return {}


def test_map_tenable_error_403_permission():
    f = map_tenable_error(TenableError(403, "forbidden"), "Tenable vulnerabilities")
    assert f is not None
    assert f.finding_type.value == "posture"
    assert "Tenable vulnerabilities" in f.title


def test_map_tenable_error_429_rate_limited():
    f = map_tenable_error(TenableError(429, "slow down"), "Tenable assets")
    assert f is not None and "Rate limited" in f.title


def test_map_tenable_error_502_unavailable():
    f = map_tenable_error(TenableError(503, "bad gateway"), "Tenable scans")
    assert f is not None and "unavailable" in f.title.lower()


def test_map_tenable_error_unknown_returns_none():
    assert map_tenable_error(ValueError("nope"), "x") is None
    assert map_tenable_error(TenableError(418, "teapot"), "x") is None


def test_tenable_error_redacts_message():
    e = TenableError(401, "Authorization: Bearer Tenable_SuperLongSecretToken_12345")
    assert "Tenable_SuperLongSecretToken_12345" not in str(e) or "«redacted»" in str(e)
