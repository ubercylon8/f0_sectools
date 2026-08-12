"""Credential files must be found by where the checkout is, not by how the client was launched."""
import os
from pathlib import Path

import pytest
from f0_sectools_core.auth.env import env_search_dirs, find_platform_env, load_platform_env

# A platform name no real .env.* uses, so the developer's own checkout can
# never satisfy a test that asserts "nothing found".
FAKE = "acmecorp"


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    """A fake checkout with a credential file at its root and a nested subdir."""
    (tmp_path / f".env.{FAKE}").write_text(f"{FAKE.upper()}_TOKEN=from-file\n")
    deep = tmp_path / "skills" / "sentinel" / "detection-coverage"
    deep.mkdir(parents=True)
    monkeypatch.delenv("F0_SECTOOLS_ENV_DIR", raising=False)
    monkeypatch.delenv(f"{FAKE.upper()}_TOKEN", raising=False)
    return tmp_path, deep


def test_finds_env_file_when_cwd_is_a_subdirectory(checkout, monkeypatch):
    """The regression: opencode launched from skills/ left every server credential-less."""
    root, deep = checkout
    monkeypatch.chdir(deep)
    assert find_platform_env(FAKE) == root / f".env.{FAKE}"


def test_load_populates_environment_from_a_subdirectory(checkout, monkeypatch):
    root, deep = checkout
    monkeypatch.chdir(deep)
    assert load_platform_env(FAKE) == root / f".env.{FAKE}"
    assert os.environ[f"{FAKE.upper()}_TOKEN"] == "from-file"


def test_missing_file_is_not_an_error(tmp_path, monkeypatch):
    """Credentials supplied as real env vars (container, systemd) is a supported deployment."""
    monkeypatch.delenv("F0_SECTOOLS_ENV_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert load_platform_env(FAKE) is None


def test_explicit_override_wins(checkout, monkeypatch, tmp_path_factory):
    """F0_SECTOOLS_ENV_DIR relocates credentials off the checkout entirely."""
    root, deep = checkout
    elsewhere = tmp_path_factory.mktemp("vault")
    (elsewhere / f".env.{FAKE}").write_text(f"{FAKE.upper()}_TOKEN=from-vault\n")
    monkeypatch.setenv("F0_SECTOOLS_ENV_DIR", str(elsewhere))
    monkeypatch.chdir(deep)
    assert load_platform_env(FAKE) == elsewhere / f".env.{FAKE}"
    assert os.environ[f"{FAKE.upper()}_TOKEN"] == "from-vault"


def test_real_environment_beats_the_file(checkout, monkeypatch):
    """A var already exported must not be clobbered by the file (dotenv override=False)."""
    root, deep = checkout
    monkeypatch.chdir(deep)
    monkeypatch.setenv(f"{FAKE.upper()}_TOKEN", "from-shell")
    load_platform_env(FAKE)
    assert os.environ[f"{FAKE.upper()}_TOKEN"] == "from-shell"


def test_search_dirs_are_ordered_and_deduplicated(checkout, monkeypatch):
    root, deep = checkout
    monkeypatch.chdir(deep)
    dirs = env_search_dirs()
    assert dirs[0] == deep, "the working directory is searched first"
    assert len(dirs) == len(set(dirs)), "no directory is searched twice"
    assert root in dirs


def test_no_server_loads_dotenv_by_a_bare_relative_path():
    """Drift guard: server #10 must not reintroduce the CWD dependency."""
    repo = Path(__file__).resolve().parents[2]
    offenders = [
        f"{p.relative_to(repo)}:{n}"
        for p in sorted(repo.glob("servers/*/*/server.py"))
        for n, line in enumerate(p.read_text().splitlines(), 1)
        if 'load_dotenv(".env.' in line
    ]
    assert offenders == [], f"use load_platform_env() from core: {offenders}"


def test_missing_vars_error_points_at_the_absent_credential_file(tmp_path, monkeypatch):
    """The message that sent a local model into a debugging loop must name the file."""
    from f0_sectools_core.auth.config import PlatformConfig

    monkeypatch.delenv("F0_SECTOOLS_ENV_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError) as e:
        PlatformConfig.from_env(FAKE.upper(), env={})
    message = str(e.value)
    assert f"{FAKE.upper()}_TENANT_ID" in message, "still lists the variable names"
    assert f"no .env.{FAKE} was found" in message
    assert "F0_SECTOOLS_ENV_DIR" in message


def test_missing_vars_error_points_at_a_present_credential_file(checkout, monkeypatch):
    from f0_sectools_core.auth.config import PlatformConfig

    root, deep = checkout
    monkeypatch.chdir(deep)
    with pytest.raises(ValueError) as e:
        PlatformConfig.from_env(FAKE.upper(), env={})
    assert f"found .env.{FAKE} in {root}" in str(e.value)


def test_missing_vars_error_never_leaks_a_value(checkout, monkeypatch):
    """Critical Rule 2: an error path is still an output path."""
    from f0_sectools_core.auth.config import PlatformConfig

    root, deep = checkout
    (root / f".env.{FAKE}").write_text(f"{FAKE.upper()}_CLIENT_SECRET=super-secret-value\n")
    monkeypatch.chdir(deep)
    with pytest.raises(ValueError) as e:
        PlatformConfig.from_env(FAKE.upper(), env={})
    assert "super-secret-value" not in str(e.value)
