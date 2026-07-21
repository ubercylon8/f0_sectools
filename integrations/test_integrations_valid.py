"""Runtime-integration drift guard.

The uv workspace is the single source of truth for which servers exist
(every ``servers/*/pyproject.toml`` declares one ``[project.scripts]`` entry).
These tests fail CI whenever a runtime template — pi's mcp.json, the Hermes
example config, or the Hermes distribution config.yaml — is missing a server,
references one that no longer exists, or leaks a real local path instead of
the placeholder. Adding server #8 without wiring it into every runtime becomes
a red build, not silent drift.
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


def test_every_server_wired_into_distribution():
    # Hermes v0.18.2 reads servers from config.yaml's `mcp_servers` (a shipped
    # mcp.json is copied but not auto-loaded by the CLI — verified live).
    cfg = yaml.safe_load(
        (ROOT / "integrations/hermes/distribution/config.yaml").read_text(encoding="utf-8")
    )
    assert _wired(cfg["mcp_servers"]) == _server_scripts(), (
        "integrations/hermes/distribution/config.yaml mcp_servers is out of sync with servers/*"
    )
    # Every server runs from the F0_SECTOOLS_DIR placeholder, never a real path.
    for s in cfg["mcp_servers"].values():
        assert "${F0_SECTOOLS_DIR}" in s["args"], s


def test_templates_use_placeholder_paths_only():
    # Files that should use ${F0_SECTOOLS_DIR}
    placeholder_required_files = {
        "integrations/hermes/config.example.yaml",
        "integrations/hermes/distribution/config.yaml",
    }
    # Files that should use /ABSOLUTE/PATH/TO/sec-tools
    legacy_placeholder_files = {"integrations/pi/mcp.json"}
    # Files that should not leak real paths but don't require a specific placeholder
    no_real_paths_files = {"integrations/hermes/distribution/distribution.yaml"}

    for rel in placeholder_required_files | legacy_placeholder_files | no_real_paths_files:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "/home/" not in text, (
            f"{rel} leaks a real local path — use {PLACEHOLDER} or ${{F0_SECTOOLS_DIR}} "
            "(rendering happens locally, e.g. scripts/sync_pi_config.py)"
        )
        if rel in placeholder_required_files:
            assert "${F0_SECTOOLS_DIR}" in text, f"{rel} lost the ${{F0_SECTOOLS_DIR}} placeholder"
        elif rel in legacy_placeholder_files:
            assert PLACEHOLDER in text, f"{rel} lost the {PLACEHOLDER} placeholder"
        # no_real_paths_files: only check for absence of /home/, no specific placeholder required


def test_distribution_manifest_valid():
    manifest = yaml.safe_load(
        (ROOT / "integrations/hermes/distribution/distribution.yaml").read_text(encoding="utf-8")
    )
    assert manifest["name"] == "f0sectools"
    assert manifest.get("version")
    assert manifest.get("hermes_requires")
    env_names = {e["name"] for e in manifest.get("env_requires", [])}
    assert "F0_SECTOOLS_DIR" in env_names, "manifest must document F0_SECTOOLS_DIR"
    # No platform secrets are ever documented as required env (they live in .env.<platform>).
    assert not (env_names & {"DEFENDER_CLIENT_SECRET", "PROJECTACHILLES_API_KEY", "LC_API_KEY"})


def test_distribution_config_valid():
    cfg = yaml.safe_load(
        (ROOT / "integrations/hermes/distribution/config.yaml").read_text("utf-8")
    )
    # Skills load from the checkout via the env placeholder — never copied, never a real path.
    assert cfg["skills"]["external_dirs"] == ["${F0_SECTOOLS_DIR}/skills"]
    # The 4 role personas ship with the distribution.
    assert {"ciso", "threat-hunter", "detection-engineer", "security-engineer"} <= set(
        cfg["agent"]["personalities"]
    )
    # The 7 MCP servers are wired here (Hermes reads mcp_servers from config.yaml).
    assert len(cfg["mcp_servers"]) == 7
    # No operator-specific model config is baked in (config.yaml is preserved on update).
    assert "model" not in cfg and "providers" not in cfg
