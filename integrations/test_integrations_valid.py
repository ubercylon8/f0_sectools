"""Runtime-integration drift guard.

The uv workspace is the single source of truth for which servers exist
(every ``servers/*/pyproject.toml`` declares one ``[project.scripts]`` entry).
These tests fail CI whenever a runtime template — pi's mcp.json or the Hermes
example config — is missing a server, references one that no longer exists,
or leaks a real local path instead of the placeholder. Adding server #8
without wiring it into every runtime becomes a red build, not silent drift.
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER = "/ABSOLUTE/PATH/TO/sec-tools"


def _server_scripts() -> set[str]:
    """Entry-point names of every workspace server (e.g. f0-defender-mcp)."""
    scripts: set[str] = set()
    for pyproject in sorted((ROOT / "servers").glob("*/pyproject.toml")):
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        entries = data.get("project", {}).get("scripts", {})
        assert entries, f"{pyproject} has no [project.scripts] entry"
        scripts.update(entries)
    return scripts


def _wired(entries: dict) -> set[str]:
    """Script names referenced by a template's server entries (last arg)."""
    return {entry["args"][-1] for entry in entries.values()}


def test_every_server_wired_into_pi_template():
    cfg = json.loads((ROOT / "integrations/pi/mcp.json").read_text(encoding="utf-8"))
    assert _wired(cfg["mcpServers"]) == _server_scripts(), (
        "integrations/pi/mcp.json is out of sync with servers/* — "
        "add/remove the server entry there (recipe step 11)"
    )


def test_every_server_wired_into_hermes_template():
    cfg = yaml.safe_load(
        (ROOT / "integrations/hermes/config.example.yaml").read_text(encoding="utf-8")
    )
    assert _wired(cfg["mcp_servers"]) == _server_scripts(), (
        "integrations/hermes/config.example.yaml is out of sync with servers/* — "
        "add/remove the server entry there (recipe step 11)"
    )


def test_templates_use_placeholder_paths_only():
    for rel in ("integrations/pi/mcp.json", "integrations/hermes/config.example.yaml"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "/home/" not in text, (
            f"{rel} leaks a real local path — use {PLACEHOLDER} "
            "(rendering happens locally, e.g. scripts/sync_pi_config.py)"
        )
        assert PLACEHOLDER in text, f"{rel} lost the {PLACEHOLDER} placeholder"
