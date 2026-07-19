"""Out-of-band confirmation for gated write actions — token issuer + approval watcher.

Two ways to authorize one gated action (both single-use, target-bound, TTL'd,
audited; the model can invoke neither):

  WATCHER (lowest friction — keep this running in a spare terminal/tmux pane):
      python scripts/confirm_action.py --watch [--notify]
  Pending gated calls appear as they happen; answer y/N. Then tell the agent
  "approved" — it repeats the identical tool call and the gate consumes the
  approval. No token is ever pasted anywhere.

  ONE-SHOT:
      python scripts/confirm_action.py --approve run_test "<target>" --platform projectachilles
      python scripts/confirm_action.py --list

  LEGACY TOKEN (kept for headless/scripted flows, e.g. live-smoke --execute):
      python scripts/confirm_action.py isolate_host <device_id> [--ttl 900]
  Paste the printed token into the tool's `confirmation_token` argument.

State lives under $F0_GATING_DIR (default ~/.f0sectools/gating), shared with
the MCP servers regardless of working directory.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import time
from collections.abc import Callable

from f0_sectools_core.gating.actions import ApprovalStore, AuditLog, TokenStore

_ACTOR = "operator-cli"


def resolve_action(action: str, platform: str) -> str:
    return action if "." in action else f"{platform}.{action}"


def _display(s: str) -> str:
    """Neutralize terminal escapes/control chars in model-influenced strings."""
    return "".join(c if c.isprintable() else "?" for c in s)


def issue_confirmation(
    action: str,
    target: str,
    ttl_s: int = 900,
    store: TokenStore | None = None,
    platform: str = "defender",
) -> str:
    store = store or TokenStore()
    return store.issue(resolve_action(action, platform), target, ttl_s)


def approve_one(
    store: ApprovalStore, audit: AuditLog, action: str, target: str, ttl_s: int = 900
) -> None:
    store.approve(action, target, ttl_s=ttl_s)
    audit.record(
        action, target, _ACTOR, "", method="approved", ref=ApprovalStore._key(action, target)[:16]
    )


def deny_one(store: ApprovalStore, audit: AuditLog, action: str, target: str) -> None:
    store.deny(action, target)
    audit.record(
        action, target, _ACTOR, "", method="denied", ref=ApprovalStore._key(action, target)[:16]
    )


def _desktop_notify(message: str) -> None:
    exe = shutil.which("notify-send")
    if exe:
        subprocess.run(  # noqa: S603 — fixed local binary, no shell, operator's own session
            [exe, "f0_sectools gated action", message], check=False
        )


def watch_once(
    store: ApprovalStore,
    audit: AuditLog,
    ask: Callable[[str], str],
    notify: Callable[[str], None] | None = None,
) -> int:
    """Handle every currently-pending request; returns how many were handled."""
    handled = 0
    for req in store.list_pending():
        action, target = str(req.get("action")), str(req.get("target"))
        d_action, d_target = _display(action), _display(target)
        if notify:
            notify(f"{d_action} -> {d_target}")
        answer = ask(f"{d_action} -> {d_target} — approve? [y/N] ").strip().lower()
        if answer == "y":
            approve_one(store, audit, action, target)
            print(f"APPROVED {d_action} -> {d_target} (15 min, single use)")
        else:
            deny_one(store, audit, action, target)
            print(f"denied {d_action} -> {d_target}")
        handled += 1
    return handled


def _watch_loop(store: ApprovalStore, audit: AuditLog, interval: float, notify: bool) -> int:
    print(f"Watching for gated-action requests ({store.requests}) — Ctrl-C to stop.")
    notifier = _desktop_notify if notify else None
    try:
        while True:
            watch_once(store, audit, ask=input, notify=notifier)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nwatcher stopped.")
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Authorize gated write actions (watcher approvals or one-shot tokens)."
    )
    parser.add_argument("action", nargs="?", help="e.g. isolate_host, run_test")
    parser.add_argument("target", nargs="?", help="the exact target the action will affect")
    parser.add_argument("--platform", default="defender")
    parser.add_argument("--ttl", type=int, default=900, help="seconds until expiry")
    parser.add_argument("--store-dir", default=None, help="override the gating state dir")
    parser.add_argument("--watch", action="store_true", help="interactive approval watcher")
    parser.add_argument("--notify", action="store_true", help="notify-send on pending items")
    parser.add_argument("--interval", type=float, default=2.0, help="watch poll seconds")
    parser.add_argument("--approve", action="store_true",
                        help="approve ACTION TARGET without a token")
    parser.add_argument("--list", action="store_true", dest="list_pending",
                        help="list pending requests")
    args = parser.parse_args(argv)

    approvals = ApprovalStore(args.store_dir)
    audit = AuditLog(str(args.store_dir) + "/audit.log") if args.store_dir else AuditLog()

    if args.watch:
        return _watch_loop(approvals, audit, args.interval, args.notify)

    if args.list_pending:
        pending = approvals.list_pending()
        if not pending:
            print("no pending gated-action requests.")
        for req in pending:
            print(f"{_display(str(req.get('action')))} -> {_display(str(req.get('target')))}")
        return 0

    if args.approve:
        if not (args.action and args.target):
            parser.error("--approve needs ACTION and TARGET")
        action = resolve_action(args.action, args.platform)
        approve_one(approvals, audit, action, args.target, ttl_s=args.ttl)
        print(f"APPROVED {action} -> {args.target} "
              f"(valid {args.ttl}s, single use) — tell the agent to retry the same call.")
        return 0

    # Legacy token mode
    if not (args.action and args.target):
        parser.error("provide ACTION and TARGET (or use --watch / --list / --approve)")
    store = TokenStore(args.store_dir) if args.store_dir else None
    token = issue_confirmation(
        args.action, args.target, ttl_s=args.ttl, store=store, platform=args.platform
    )
    print(f"Confirmation token for {resolve_action(args.action, args.platform)} "
          f"on {args.target}:")
    print(token)
    print(f"(valid {args.ttl}s, single use) — paste into the tool's "
          "confirmation_token argument.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
