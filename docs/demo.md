# Demo — a tool call, end to end (no live platform, no GPU)

This runs an f0_sectools read tool against a **fake client** with canned data in
the exact shape the live Tenable Workbenches API returns, then redacts the result
at the server boundary — the same path a real call takes. Reproduce it yourself:

```bash
uv run python scripts/demo_mock_findings.py
```

A model asks "what are our worst vulnerabilities?" → the agent selects
`list_top_vulnerabilities(severity_min="high")` → the server returns a redacted,
normalized finding:

```json
[
  {
    "schema_version": "1.0",
    "source": "tenable",
    "finding_type": "misconfig",
    "severity": "critical",
    "title": "Tenable: Apache Log4j Remote Code Execution (Log4Shell) (plugin 155999)",
    "entity": {
      "kind": "rule",
      "id": "155999",
      "name": "Apache Log4j Remote Code Execution (Log4Shell)"
    },
    "evidence": [
      {
        "key": "affected_hosts",
        "value": "12"
      },
      {
        "key": "cvss",
        "value": "10.0"
      }
    ],
    "recommended_action": {
      "summary": "Review affected hosts and remediate; see get_vulnerability_info for the fix.",
      "gated_action": null,
      "confidence": "medium"
    },
    "references": [
      {
        "type": "tenable_plugin",
        "id": "155999",
        "url": null
      }
    ],
    "observed_at": null
  }
]
```

Every tool returns this same [findings schema](../CLAUDE.md#the-findings-schema),
so an agent — and a small local model especially — parses and chains results
predictably. On the [scorecard](../evals/SCORECARD.md), every tested model drives
these tools at 100%/100% per server.
