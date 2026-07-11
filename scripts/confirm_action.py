"""Out-of-band confirmation-token generator for gated write actions.

Run this in YOUR terminal to authorize one gated action. The model cannot invoke
this to read its output — the token exists only in your shell and the single tool
call you paste it into.

Usage:
    python scripts/confirm_action.py isolate_host <device_id> [--ttl 900]
    python scripts/confirm_action.py release_host <device_id>

Paste the printed token into the tool's `confirmation_token` argument.
"""
from __future__ import annotations

import argparse

from f0_sectools_core.gating.actions import TokenStore


def issue_confirmation(
    action: str,
    target: str,
    ttl_s: int = 900,
    store: TokenStore | None = None,
    platform: str = "defender",
) -> str:
    store = store or TokenStore()
    gated_name = action if "." in action else f"{platform}.{action}"
    return store.issue(gated_name, target, ttl_s)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Issue a single-use confirmation token.")
    parser.add_argument("action", help="e.g. isolate_host, release_host")
    parser.add_argument("target", help="the device_id the action will affect")
    parser.add_argument("--platform", default="defender")
    parser.add_argument("--ttl", type=int, default=900, help="seconds until the token expires")
    parser.add_argument("--store-dir", default=None, help="override the pending-token dir")
    args = parser.parse_args(argv)

    store = TokenStore(args.store_dir) if args.store_dir else None
    token = issue_confirmation(
        args.action, args.target, ttl_s=args.ttl, store=store, platform=args.platform
    )
    print(f"Confirmation token for {args.platform}.{args.action} on {args.target}:")
    print(token)
    print(f"(valid {args.ttl}s, single use) — paste into the tool's confirmation_token argument.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
