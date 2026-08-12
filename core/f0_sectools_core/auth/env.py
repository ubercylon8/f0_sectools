"""Locate a platform's ``.env`` file by searching, not by trusting the working directory.

An MCP client starts a server with whatever working directory it happens to
have: opencode launched from a subdirectory of the checkout, a systemd unit
from ``/``, a desktop client from ``$HOME``. A bare
``load_dotenv(".env.defender")`` resolves against that directory, so it
silently loads nothing and the server fails later with an opaque "missing
environment variables" error that points at the credentials rather than at
the launch context.

Resolving by search makes the credential location a property of the checkout
instead of a property of how the client was launched.

Search order, highest precedence first:

1. ``$F0_SECTOOLS_ENV_DIR`` -- an explicit operator override, for keeping
   credentials outside the checkout entirely.
2. The working directory and each of its ancestors.
3. The installed package's directory and each of its ancestors -- reached
   when the checkout is nowhere near the working directory at all.

Only variables named ``<PLATFORM>_*`` are injected; anything else in the
file is ignored, so one platform's file can neither set another's
credential nor alter the process environment.

A file that is *not* found is not an error: supplying credentials as real
environment variables is a supported deployment, and ``python-dotenv`` never
overwrites a variable that is already set, so the surrounding environment
always wins over the file.

Secrets read here enter this process's environment only. They are never
logged, never returned in tool output, and never placed in model context.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import dotenv_values

__all__ = ["env_search_dirs", "find_platform_env", "load_platform_env"]


def env_search_dirs() -> list[Path]:
    """Directories searched for a credential file, highest precedence first."""
    candidates: list[Path] = []

    override = os.environ.get("F0_SECTOOLS_ENV_DIR")
    if override:
        candidates.append(Path(override).expanduser())

    try:
        cwd = Path.cwd()
    except OSError:  # working directory deleted out from under the process
        cwd = None
    if cwd is not None:
        candidates.extend([cwd, *cwd.parents])

    package = Path(__file__).resolve()
    candidates.extend(package.parents)

    seen: set[Path] = set()
    ordered: list[Path] = []
    for directory in candidates:
        if directory not in seen:
            seen.add(directory)
            ordered.append(directory)
    return ordered


def find_platform_env(platform: str) -> Path | None:
    """Return the path to ``.env.<platform>``, or None if no checkout holds one."""
    filename = f".env.{platform}"
    for directory in env_search_dirs():
        candidate = directory / filename
        if candidate.is_file():
            return candidate
    return None


def load_platform_env(platform: str) -> Path | None:
    """Load ``.env.<platform>`` into the environment; return where it came from.

    Returns None when no file exists, leaving the surrounding environment as
    the credential source. Callers use the return value for diagnostics only
    -- never log or return the file's *contents*.
    """
    path = find_platform_env(platform)
    if path is None:
        return None
    # Only this platform's own variables are injected. Two reasons, both
    # Critical Rules: Rule 7 is per-platform credential isolation, and a file
    # loaded wholesale could also set process-wide knobs -- HTTPS_PROXY is the
    # sharp one, since httpx honours it (trust_env) on calls carrying a live
    # token. `setdefault` keeps dotenv's override=False semantics: a variable
    # already exported wins.
    prefix = f"{platform.upper()}_"
    for key, value in dotenv_values(path).items():
        if value is not None and key.startswith(prefix):
            os.environ.setdefault(key, value)
    return path
