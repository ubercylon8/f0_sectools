"""Test fixtures for the Sentinel server."""
from __future__ import annotations

import pytest
from f0_sentinel_mcp import probe


class FakeClient:
    """Fake SentinelClient: canned KQL rows by substring, or a configured error."""

    def __init__(self, rows=None, arm=None, raise_on=None, retention_days=30, has_arm=True):
        self._rows = rows or {}
        self._arm = arm or {}
        self._raise = raise_on or {}
        self.retention_days = retention_days
        self.has_arm = has_arm
        self.workspace_id = "ws-test"
        self.queries: list[str] = []

    async def query(self, kql, timespan):
        self.queries.append(kql)
        for needle, err in self._raise.items():
            if needle in kql:
                raise err
        # Longest-match-first so a specific fixture beats a generic one.
        for needle, rows in sorted(self._rows.items(), key=lambda kv: -len(kv[0])):
            if needle in kql:
                return rows
        return []

    async def arm_list(self, resource):
        for needle, err in self._raise.items():
            if needle == resource:
                raise err
        return self._arm.get(resource, [])


@pytest.fixture
def fake():
    return FakeClient


@pytest.fixture(autouse=True)
def _reset_probe_cache():
    """The capability probe caches per workspace for the process lifetime; clear
    it around every test so one test's table set cannot leak into the next."""
    probe.reset_cache()
    yield
    probe.reset_cache()
