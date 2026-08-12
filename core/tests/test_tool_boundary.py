"""No exception may leave a tool unredacted (Critical Rules 3 and 4)."""
import ast
import asyncio
import pathlib

import pytest
from f0_sectools_core.redaction.boundary import (
    MAX_ERROR_CHARS,
    guarded_tool,
    unexpected_error_finding,
)
from f0_sectools_core.redaction.patterns import REDACTED
from f0_sectools_core.reports.sections import DEGRADATION_MARKERS

REPO = pathlib.Path(__file__).resolve().parents[2]


async def test_unmapped_exception_becomes_a_finding_instead_of_raising():
    @guarded_tool("sentinel")
    async def tool():
        raise ConnectionError("failed to resolve internal-host.example")

    out = await tool()
    assert len(out) == 1
    assert out[0]["source"] == "sentinel"
    assert out[0]["finding_type"] == "posture"
    assert "ConnectionError" in out[0]["title"]


async def test_guard_is_transparent_when_nothing_raises():
    @guarded_tool("sentinel")
    async def tool():
        return [{"ok": True}]

    assert await tool() == [{"ok": True}]


async def test_error_text_is_redacted():
    """An error path is an output path: Critical Rule 3 applies to it too."""

    @guarded_tool("defender")
    async def tool():
        raise RuntimeError("upstream rejected Bearer abcdefghijklmnop1234567890")

    out = await tool()
    blob = str(out[0])
    assert "abcdefghijklmnop1234567890" not in blob
    assert REDACTED in blob


async def test_long_error_is_truncated():
    """An exception can carry a whole HTTP body; bounded output is a repo rule."""

    @guarded_tool("tenable")
    async def tool():
        raise RuntimeError("x" * 5000)

    finding = (await tool())[0]
    err = next(e for e in finding["evidence"] if e["key"] == "error")
    assert len(err["value"]) <= MAX_ERROR_CHARS + 1  # +1 for the ellipsis
    assert err["value"].endswith("…")


async def test_cancellation_still_propagates():
    """Catching BaseException would stop a shutting-down server from shutting down."""

    @guarded_tool("entra")
    async def tool():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await tool()


def test_title_is_a_report_degradation_marker():
    """A transport failure must render as 'not assessed', not as a security finding."""
    f = unexpected_error_finding("purview", "get_dlp_summary", TimeoutError("slow"))
    assert any(m in f.title for m in DEGRADATION_MARKERS)


def test_guard_preserves_the_wrapped_identity():
    """MCP derives tool name/description from the function; the guard must be invisible."""

    @guarded_tool("intune")
    async def list_managed_devices():
        """Original docstring."""

    assert list_managed_devices.__name__ == "list_managed_devices"
    assert list_managed_devices.__doc__ == "Original docstring."


def _tool_decorators(path):
    """(function name, [decorator nodes]) for every @mcp.tool() in a server module."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and any(
            isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "tool"
            for d in node.decorator_list
        ):
            yield node.name, node.decorator_list


@pytest.mark.parametrize(
    "server", sorted(REPO.glob("servers/*/*/server.py")), ids=lambda p: p.parts[-3]
)
def test_every_registered_tool_is_guarded(server):
    """Drift guard: a new tool -- or a new server -- cannot silently skip the boundary."""
    sources = set()
    unguarded = []
    for name, decorators in _tool_decorators(server):
        guards = [
            d for d in decorators
            if isinstance(d, ast.Call) and getattr(d.func, "id", "") == "guarded_tool"
        ]
        if not guards:
            unguarded.append(name)
            continue
        sources.update(
            a.value for g in guards for a in g.args if isinstance(a, ast.Constant)
        )
    assert unguarded == [], f"tools missing @guarded_tool: {unguarded}"
    assert len(sources) == 1, f"one server must report one source, got {sources}"
    assert sources.pop(), "guarded_tool source must be a non-empty string"
