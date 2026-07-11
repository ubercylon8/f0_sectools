import importlib.util
from pathlib import Path

from f0_sectools_core.gating.actions import TokenStore

# Load scripts/confirm_action.py by path (scripts/ is not an installed package).
_SPEC = importlib.util.spec_from_file_location(
    "confirm_action", Path(__file__).resolve().parents[1] / "confirm_action.py"
)
confirm_action = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(confirm_action)


def test_issue_confirmation_returns_consumable_token(tmp_path):
    store = TokenStore(str(tmp_path / "pending"))
    tok = confirm_action.issue_confirmation("isolate_host", "web-01", store=store)
    # The gated name is namespaced by platform; token must consume under it.
    assert store.consume("defender.isolate_host", "web-01", tok) is True


def test_main_prints_token(tmp_path, capsys):
    rc = confirm_action.main(
        ["isolate_host", "web-01", "--store-dir", str(tmp_path / "pending")]
    )
    assert rc == 0
    out = capsys.readouterr().out
    # A token is printed and it is consumable from the same store dir.
    store = TokenStore(str(tmp_path / "pending"))
    printed = [w for line in out.splitlines() for w in line.split() if len(w) > 20]
    assert printed, "expected a token in stdout"
    assert store.consume("defender.isolate_host", "web-01", printed[-1]) is True
