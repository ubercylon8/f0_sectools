"""Mock demo — a Tenable read tool returning redacted findings.

No live platform, no GPU: the tool is driven against a fake client with canned
data, exactly the shape the live Workbenches API returns. Run:

    uv run python scripts/demo_mock_findings.py
"""
from __future__ import annotations

import asyncio
import json

from f0_sectools_core.redaction.redact import redact_obj
from f0_tenable_mcp import tools


class FakeTenable:
    """Stand-in for TenableClient: canned Workbenches responses by path prefix."""

    async def get(self, path: str, params: dict | None = None) -> dict:
        if path.startswith("/workbenches/vulnerabilities"):
            return {
                "vulnerabilities": [
                    {
                        "plugin_id": 155999,
                        "plugin_name": "Apache Log4j Remote Code Execution (Log4Shell)",
                        "severity": 4,
                        "count": 12,
                        "cvss3_base_score": 10.0,
                    },
                    {
                        "plugin_id": 51192,
                        "plugin_name": "SSL Certificate Cannot Be Trusted",
                        "severity": 2,
                        "count": 40,
                        "cvss_base_score": 6.4,
                    },
                ]
            }
        return {}


async def main() -> None:
    tio = FakeTenable()
    findings = await tools.list_top_vulnerabilities(tio, severity_min="high", limit=3)
    payload = [redact_obj(f.model_dump()) for f in findings]
    print(json.dumps(payload, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
