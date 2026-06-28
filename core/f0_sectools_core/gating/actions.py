"""Gated write-action machinery: config flag + confirmation token + audit log.

A small local model must never be able to take a state-changing action on a live
platform by itself. Every gated action requires BOTH an explicit operator-set
flag AND a per-action human confirmation token, and is recorded to a local audit
trail. This module is the single hard stop for all write/response actions.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any


class GateDenied(Exception):
    """Raised when a gated action is attempted without flag or token."""


class AuditLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else Path("audit-logs/actions.log")

    def record(self, action: str, target: str, actor: str, token: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"action": action, "target": target, "actor": actor, "token": token}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


class GatedAction:
    def __init__(self, name: str, enabled: bool, audit: AuditLog) -> None:
        self.name = name
        self.enabled = enabled
        self.audit = audit

    def execute(
        self,
        *,
        target: str,
        actor: str,
        token: str | None,
        run: Callable[[], Any],
    ) -> Any:
        if not self.enabled:
            raise GateDenied(
                f"Action '{self.name}' is disabled. Set the platform write flag to enable it."
            )
        if not token:
            raise GateDenied(f"Action '{self.name}' requires a human confirmation token.")
        result = run()
        self.audit.record(self.name, target, actor, token)
        return result
