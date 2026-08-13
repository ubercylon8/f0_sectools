"""Offline tests for the pi config renderer (no live pi install touched)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import sync_pi_config as sync
from scripts.sync_pi_config import PLACEHOLDER, TEMPLATE, render_mcp_json


def test_render_substitutes_path_and_uv_and_stays_valid_json():
    rendered = render_mcp_json(
        TEMPLATE.read_text(encoding="utf-8"), Path("/opt/checkout"), "/usr/bin/uv"
    )
    cfg = json.loads(rendered)
    assert PLACEHOLDER not in rendered
    for entry in cfg["mcpServers"].values():
        assert entry["command"] == "/usr/bin/uv"
        assert "/opt/checkout" in entry["args"]


def test_render_rejects_broken_template():
    with pytest.raises(json.JSONDecodeError):
        render_mcp_json('{"mcpServers": ', Path("/opt/checkout"), "uv")


def test_sync_preserves_servers_this_repo_does_not_own(tmp_path, monkeypatch):
    """A live pi install commonly carries MCP servers from other checkouts —
    this machine has `f0-library` from the sibling repo. Rendering the template
    wholesale silently deletes them: the operator asked to add a server and
    lost one, with the only trace a .bak file.
    """
    pi_home = tmp_path / "agent"
    pi_home.mkdir()
    (pi_home / "mcp.json").write_text(json.dumps({"mcpServers": {
        "f0-library": {"command": "uv", "args": ["run", "f0-library-mcp"]},
        "f0-defender": {"command": "uv", "args": ["run", "--stale", "f0-defender-mcp"]},
    }}))
    sync.main(["--pi-home", str(pi_home)])
    result = json.loads((pi_home / "mcp.json").read_text())["mcpServers"]
    assert "f0-library" in result, "a foreign server must survive the sync"
    assert "f0-sentinel" in result, "every server this repo ships must be installed"
    assert "--stale" not in json.dumps(result["f0-defender"]), "ours are refreshed"
