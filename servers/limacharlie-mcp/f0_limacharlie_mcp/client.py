"""Thin wrapper over the limacharlie v2 SDK — exposes only the read methods the
tools need, returning plain Python (lists/dicts). The SDK is synchronous; the
server runs these in a worker thread.
"""
from __future__ import annotations

from typing import Any

from f0_sectools_core.auth.config import LimaCharlieConfig
from limacharlie.client import Client
from limacharlie.sdk.dr_rules import DRRules
from limacharlie.sdk.organization import Organization
from limacharlie.sdk.search import Search
from limacharlie.sdk.sensor import Sensor


class LimaCharlieClient:
    def __init__(self, config: LimaCharlieConfig) -> None:
        self._client = Client(oid=config.oid, api_key=config.api_key, uid=config.uid)
        self._org = Organization(self._client)

    def org_info(self) -> dict[str, Any]:
        return self._org.get_info()

    def org_stats(self) -> dict[str, Any]:
        return self._org.get_stats()

    def list_sensors(self, online_only: bool = False, limit: int = 50) -> list[dict[str, Any]]:
        return list(self._org.list_sensors(is_online_only=online_only, limit=limit))

    def find_sensor(self, hostname: str) -> list[dict[str, Any]]:
        # find_sensors_by_hostname returns only {"sid": [[sid, hostname], ...]} — no
        # platform/online detail. list_sensors(with_hostname_prefix=...) returns the
        # FULL sensor dicts (same shape as list_sensors), which the tool can render.
        return list(self._org.list_sensors(with_hostname_prefix=hostname))

    def get_sensor_tags(self, sid: str) -> list[str]:
        # Tags are NOT in the sensor record — they live behind /{sid}/tags. Without
        # them a dormant (lc:sleeper) host is indistinguishable from a quiet one.
        return Sensor(self._org, sid).get_tags()

    def count_sensors_with_tag(self, tag: str) -> int:
        # Live shape: a sid->info mapping ({<sid>: {...}, ...}); some responses nest
        # a pair list under "sid" instead — count either without assuming one.
        resp = self._org.find_sensors_by_tag(tag)
        if isinstance(resp, dict):
            nested = resp.get("sid")
            return len(nested) if isinstance(nested, list) else len(resp)
        return len(resp or [])

    def list_dr_rules(self, namespace: str = "general") -> dict[str, Any]:
        return DRRules(self._org).list(namespace=namespace)

    def list_detections(
        self, start: int, end: int, limit: int = 50, category: str | None = None
    ) -> list[dict[str, Any]]:
        return list(self._org.get_detections(start, end, limit=limit, category=category))

    def query(self, lcql: str, start: int, end: int, limit: int = 50) -> list[dict[str, Any]]:
        return list(Search(self._org).execute(lcql, start_time=start, end_time=end, limit=limit))
