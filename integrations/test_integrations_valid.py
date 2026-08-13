"""Runtime-integration drift guard.

The uv workspace is the single source of truth for which servers exist
(every ``servers/*/pyproject.toml`` declares one ``[project.scripts]`` entry).
These tests fail CI whenever a runtime template — pi's mcp.json, the Hermes
example config, the Hermes distribution config.yaml, or the generic
examples/mcp/mcp.json — is missing a server,
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


def _gated_write_tools() -> set[str]:
    """Names of every gated-write tool the pa-actions server actually registers.

    Derived from the live FastMCP registry rather than hardcoded, so adding a
    fifth gated write cannot silently escape opencode's "ask" approval: the tool
    appears here the moment it is registered, and the assertion below fails until
    the permission is wired.

    A gated write is identified by its `confirmation_token` parameter — the same
    signal scripts/gen_docs.py uses to badge these tools in the reference docs.
    """
    import asyncio
    import importlib

    module = importlib.import_module("f0_pa_actions_mcp.server")
    tools = asyncio.run(module.mcp.list_tools())
    gated = {
        t.name
        for t in tools
        if "confirmation_token" in (t.input_schema or {}).get("properties", {})
    }
    assert gated, "no gated-write tools found — the detection signal has changed"
    return gated


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
    # The gated-WRITE server ships disabled here too (parity with the distribution) —
    # writes are an explicit opt-in; a missing or `true` value must fail CI.
    assert cfg["mcp_servers"]["f0-pa-actions"].get("enabled") is False


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


def test_every_server_wired_into_generic_mcp_example():
    cfg = json.loads((ROOT / "examples/mcp/mcp.json").read_text(encoding="utf-8"))
    assert _wired(cfg["mcpServers"]) == _server_scripts(), (
        "examples/mcp/mcp.json is out of sync with servers/* — "
        "add/remove the server entry there (recipe step 11)"
    )


def test_generic_mcp_example_warns_about_the_gated_write_server():
    """The generic MCP schema has no `enabled` field, so the README is the only guard.

    Every other template ships `f0-pa-actions` DISABLED — opencode via
    `"enabled": false`, Hermes via its own disabled-by-default entry. The generic
    MCP config format has no equivalent, so this template ships the gated-write
    server reachable as soon as `.env.projectachilles` is populated, and a written
    caveat is the entire mitigation. If someone deletes that paragraph the template
    silently arms a write-capable server for any client that copies it.

    Conditional on purpose: remove `f0-pa-actions` from the JSON and the caveat is
    no longer required.
    """
    cfg = json.loads((ROOT / "examples/mcp/mcp.json").read_text(encoding="utf-8"))
    if "f0-pa-actions" not in cfg["mcpServers"]:
        return
    readme = (ROOT / "examples/mcp/README.md").read_text(encoding="utf-8")
    # Scoped to the paragraph, not the file: a whole-file substring search would
    # still pass if this caveat were deleted while "gated-write" survived in some
    # unrelated paragraph, which is exactly the deletion this test exists to catch.
    paragraphs = [p for p in readme.split("\n\n") if "f0-pa-actions" in p]
    assert paragraphs, (
        "examples/mcp/mcp.json ships the gated-write server but examples/mcp/README.md "
        "never names it — the caveat is this template's only safeguard"
    )
    assert any("gated-write" in p.lower() for p in paragraphs), (
        "examples/mcp/README.md names f0-pa-actions but no longer explains, in the same "
        "paragraph, that it is gated-write"
    )


def test_templates_use_placeholder_paths_only():
    # Files that should use ${F0_SECTOOLS_DIR}
    placeholder_required_files = {
        "integrations/hermes/config.example.yaml",
        "integrations/hermes/distribution/config.yaml",
    }
    # Files that should use /ABSOLUTE/PATH/TO/sec-tools
    legacy_placeholder_files = {"integrations/pi/mcp.json", "examples/mcp/mcp.json"}
    # Files that should not leak real paths but don't require a specific placeholder
    no_real_paths_files = {
        "integrations/hermes/distribution/distribution.yaml",
        "opencode.json",  # in-repo project config: relative paths only
    }

    for rel in placeholder_required_files | legacy_placeholder_files | no_real_paths_files:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for real_root in ("/home/", "/Users/"):
            assert real_root not in text, (
                f"{rel} leaks a real local path ({real_root}) — use {PLACEHOLDER} or "
                "${F0_SECTOOLS_DIR} (rendering happens locally, e.g. scripts/sync_pi_config.py)"
            )
        if rel in placeholder_required_files:
            assert "${F0_SECTOOLS_DIR}" in text, f"{rel} lost the ${{F0_SECTOOLS_DIR}} placeholder"
        elif rel in legacy_placeholder_files:
            assert PLACEHOLDER in text, f"{rel} lost the {PLACEHOLDER} placeholder"
        # no_real_paths_files: only check for absence of /home/, no specific placeholder required


def test_every_server_wired_into_opencode_config():
    # opencode reads the project config from the repo root; commands are RELATIVE
    # (`uv run --directory . <script>`) because the config lives in the checkout.
    cfg = json.loads((ROOT / "opencode.json").read_text(encoding="utf-8"))
    # opencode uses a single `command` ARRAY (not the command+args split the
    # Hermes/pi templates use), so derive the script name from its last element.
    wired = {s["command"][-1] for s in cfg["mcp"].values()}
    assert wired == _server_scripts(), (
        "opencode.json mcp is out of sync with servers/* (recipe step 11)"
    )
    for name, s in cfg["mcp"].items():
        assert s["type"] == "local", name
        assert s["command"][:4] == ["uv", "run", "--directory", "."], name
    # The gated-WRITE server ships DISABLED — the opencode model has shell, so
    # the confirmation gate is not forge-resistant; writes are an explicit opt-in.
    assert cfg["mcp"]["f0-pa-actions"]["enabled"] is False
    # Runtime defense-in-depth: when an operator DOES enable the server, every
    # WRITE tool call must hit opencode's interactive "ask" approval (a TUI
    # prompt the model cannot forge). Reads stay friction-free.
    for write_tool in sorted(_gated_write_tools()):
        assert cfg["permission"].get(f"f0-pa-actions_{write_tool}") == "ask", write_tool
    # Never touch the operator's model/provider setup from the project config.
    assert "model" not in cfg and "provider" not in cfg


def _skill_names_to_dirs() -> dict[str, Path]:
    """Frontmatter `name` -> skill directory, for every skills/*/*/SKILL.md."""
    out: dict[str, Path] = {}
    for skill_md in sorted(ROOT.glob("skills/*/*/SKILL.md")):
        text = skill_md.read_text(encoding="utf-8")
        assert text.startswith("---"), f"{skill_md} missing frontmatter"
        meta = yaml.safe_load(text.split("---", 2)[1])
        out[meta["name"]] = skill_md.parent
    return out


def test_opencode_skill_symlinks_complete_and_valid():
    # opencode (>=1.18) discovers .opencode/skills/*/SKILL.md natively; each entry
    # is a committed RELATIVE symlink to the portable skill dir (Critical Rule 9:
    # one skill set, wiring only). Adding skill #23 without a link = red build.
    links_dir = ROOT / ".opencode/skills"
    expected = _skill_names_to_dirs()
    assert links_dir.is_dir(), ".opencode/skills is missing"
    actual = {p.name: p for p in links_dir.iterdir()}
    assert set(actual) == set(expected), (
        ".opencode/skills is out of sync with skills/* — "
        "add/remove the symlink (recipe step 11)"
    )
    for name, link in actual.items():
        assert link.is_symlink(), f"{link} must be a symlink, not a copy"
        assert not link.readlink().is_absolute(), f"{link} must use a relative target"
        assert link.resolve() == expected[name].resolve(), (
            f"{link} resolves to {link.resolve()}, expected {expected[name]}"
        )
        assert (link / "SKILL.md").is_file(), f"{link}/SKILL.md unreadable via symlink"


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
    # The 9 MCP servers are wired here (Hermes reads mcp_servers from config.yaml).
    assert len(cfg["mcp_servers"]) == 9
    # The gated-WRITE server ships DISABLED — writes are an explicit opt-in
    # (the model has shell in Hermes v0.18.2, so the confirmation gate is not
    # forge-resistant). Read-only servers stay enabled.
    assert cfg["mcp_servers"]["f0-pa-actions"]["enabled"] is False
    # No operator-specific model config is baked in (config.yaml is preserved on update).
    assert "model" not in cfg and "providers" not in cfg


def test_distribution_manifest_names_every_platform_it_ships():
    """The manifest description is what an operator reads before installing.

    It listed six platforms while the distribution wired nine — Purview and
    Sentinel shipped and nobody updated the prose, so the profile under-sold
    itself and misdescribed its own contents. `mcp_servers` completeness was
    already guarded; the sentence a human reads was not.
    """
    manifest = yaml.safe_load(
        (ROOT / "integrations/hermes/distribution/distribution.yaml").read_text(encoding="utf-8")
    )
    description = manifest["description"].lower()
    missing = sorted(
        {p.name.removesuffix("-mcp").split("-")[0] for p in (ROOT / "servers").iterdir()
         if p.is_dir()}
        - {word for word in description.replace(",", " ").split()}
    )
    # projectachilles-actions collapses onto projectachilles; both start the same.
    missing = [m for m in missing if m not in description]
    assert missing == [], f"distribution.yaml description omits: {missing}"


def test_distribution_version_tracks_the_repo_version():
    """A profile pinned at an old version tells operators nothing changed."""
    manifest = yaml.safe_load(
        (ROOT / "integrations/hermes/distribution/distribution.yaml").read_text(encoding="utf-8")
    )
    root = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert str(manifest["version"]) == root["project"]["version"]
