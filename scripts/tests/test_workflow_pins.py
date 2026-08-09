"""Drift guard: every GitHub Actions reference stays pinned to a commit.

A tag like `@v3` is a mutable pointer owned by a third party. `gitleaks-action`
reads this repo's full git history and `claude-code-action` reads its diff; a tag
repointed upstream changes what runs here with no commit on this side. Dependabot
updates SHA pins from the trailing version comment, so pinning costs nothing in
maintenance — the comment is what makes the pin legible and updatable, which is
why it is required rather than optional.

`.github/workflows/zizmor.yml` enforces the same rule in CI and rather more
besides (template injection, excessive permissions). This guard exists because
zizmor needs the network and the suite must stay offline: `uv run pytest` should
catch a reintroduced tag before it reaches a runner.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).parent.parent.parent
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))

_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def test_workflows_exist():
    """A glob that silently matches nothing would make every test below vacuous."""
    assert len(WORKFLOWS) >= 9, [w.name for w in WORKFLOWS]


def test_every_action_is_pinned_to_a_commit_sha():
    unpinned: list[str] = []
    for wf in WORKFLOWS:
        for lineno, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = _USES.match(line)
            if not m or "@" not in m.group("ref"):
                continue
            if not _SHA.match(m.group("ref").rsplit("@", 1)[1]):
                unpinned.append(f"{wf.name}:{lineno} {m.group('ref')}")
    assert unpinned == [], f"actions pinned to a mutable tag: {unpinned}"


def test_every_pin_carries_a_version_comment():
    """The SHA says what runs; the comment says which release it is."""
    bare: list[str] = []
    for wf in WORKFLOWS:
        for lineno, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = _USES.match(line)
            if not m or not _SHA.match(m.group("ref").rsplit("@", 1)[-1]):
                continue
            if not re.search(r"#\s*v?\d", m.group("rest")):
                bare.append(f"{wf.name}:{lineno} {m.group('ref')}")
    assert bare == [], f"SHA pins with no version comment: {bare}"


def test_container_images_are_pinned_by_digest():
    """A `container: image:` tag is mutable in exactly the way an action tag is."""
    unpinned: list[str] = []
    for wf in WORKFLOWS:
        data = yaml.safe_load(wf.read_text(encoding="utf-8"))
        for job_name, job in (data.get("jobs") or {}).items():
            container = job.get("container")
            image = container.get("image") if isinstance(container, dict) else container
            if isinstance(image, str) and "@sha256:" not in image:
                unpinned.append(f"{wf.name}:{job_name} {image}")
    assert unpinned == [], f"container images not pinned by digest: {unpinned}"


def test_no_workflow_grants_contents_write():
    """No job here writes to the repo. A `contents: write` grant is a review signal."""
    offenders: list[str] = []
    for wf in WORKFLOWS:
        data = yaml.safe_load(wf.read_text(encoding="utf-8"))
        scopes = [("workflow", data.get("permissions"))]
        scopes += [(j, job.get("permissions")) for j, job in (data.get("jobs") or {}).items()]
        for where, perms in scopes:
            if isinstance(perms, dict) and perms.get("contents") == "write":
                offenders.append(f"{wf.name}:{where}")
    assert offenders == [], f"contents: write granted in: {offenders}"


# `uvx <tool>` resolves to whatever PyPI serves at run time — the same mutable
# reference an action tag is, and it executes third-party code in CI. Accepted
# forms: `uvx tool@1.2.3`, `uvx tool==1.2.3`, `uvx --from pkg==1.2.3 tool`.
_UVX = re.compile(r"\buvx\s+(?P<spec>(?:--from\s+)?\S+)")

# The whole version token must be numeric-dotted. Two weaker checks were tried and
# both let floating specs through: presence of a separator accepts `tool@latest`,
# and a digit *after* the separator accepts `pkg==1.*` and `tool@1.x`. A pin has to
# name one version, so validate the entire token rather than its first character.
_VERSION = re.compile(r"(?:@|==)(?P<version>\S+)$")
_EXACT = re.compile(r"\d+(?:\.\d+)*")


def is_pinned_spec(spec: str) -> bool:
    """Does `spec` name exactly one version?

    >>> is_pinned_spec("zizmor@1.29.0")
    True
    >>> is_pinned_spec("zizmor@latest")
    False
    >>> is_pinned_spec("pip-audit==1.*")
    False

    Known limitation, stated rather than hidden: a prerelease pin such as
    `==2.10.1rc1` names exactly one version too, but is not accepted because
    `_EXACT` is numeric-dotted only. No CI tool here is pinned to a prerelease;
    widen `_EXACT` rather than working around this if one ever needs to be.
    """
    m = _VERSION.search(spec)
    return bool(m and _EXACT.fullmatch(m.group("version")))


# (spec, pinned?) — the contract, stated rather than implied. Every False here is
# a form that resolves to something different tomorrow than it does today.
_SPEC_CASES = [
    ("zizmor@1.29.0", True),
    ("pip-audit==2.10.1", True),
    ("shellcheck-py==0.11.0.1", True),
    ("pip-audit==2.10", True),
    ("zizmor", False),
    ("zizmor@latest", False),
    ("zizmor@main", False),
    ("zizmor@v1.29.0", False),          # a tag, not a version
    ("pip-audit==1.*", False),          # wildcard: any 1.x
    ("pip-audit==2.10.1rc1", False),    # names one version, but see the docstring
]


@pytest.mark.parametrize(("spec", "pinned"), _SPEC_CASES)
def test_is_pinned_spec(spec, pinned):
    assert is_pinned_spec(spec) is pinned


def test_uvx_tools_are_version_pinned():
    """A blocking gate should change when someone bumps it, not when PyPI moves.

    Dependabot cannot see inside a `run:` block, so these pins are maintained by
    hand. That is the trade: a new zizmor audit or shellcheck check arrives when
    a person raises the version and reads what it newly flags, rather than as a
    red build on an unrelated PR.
    """
    unpinned: list[str] = []
    for wf in WORKFLOWS:
        for lineno, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for m in _UVX.finditer(line):
                spec = m.group("spec").removeprefix("--from").strip()
                if not is_pinned_spec(spec):
                    unpinned.append(f"{wf.name}:{lineno} uvx {spec}")
    assert unpinned == [], f"uvx tools with no version pin: {unpinned}"
