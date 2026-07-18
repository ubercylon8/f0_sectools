"""Offline tests for the pi config renderer (no live pi install touched)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

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
