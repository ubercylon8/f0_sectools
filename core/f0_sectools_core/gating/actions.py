"""Gated write-action machinery: config flag + single-use confirmation token + audit.

A small local model must never be able to take a state-changing action on a live
platform by itself. Every gated action requires BOTH an explicit operator-set
flag AND a per-action human confirmation token (issued out-of-band, so the model
never sees it), and is recorded to a local audit trail. This module is the single
hard stop for all write/response actions.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any


class GateDenied(Exception):
    """Raised when a gated action is attempted without the flag or a valid token."""


class AuditLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else Path("audit-logs/actions.log")

    def record(self, action: str, target: str, actor: str, token: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        token_ref = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else ""
        entry = {"action": action, "target": target, "actor": actor, "token_ref": token_ref}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


class TokenStore:
    """Issues and validates single-use confirmation tokens.

    Only the SHA-256 hash of a token is persisted, bound to (action, target,
    expires_at). The plaintext token lives only in the operator's terminal (from
    ``scripts/confirm_action.py``) and the single in-flight tool call — never on
    disk, never in model context.
    """

    def __init__(self, dir: str | None = None) -> None:
        self.dir = Path(dir) if dir else Path("audit-logs/pending")

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _sweep(self) -> None:
        if not self.dir.is_dir():
            return
        now = time.time()
        for f in self.dir.glob("*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if float(rec.get("expires_at", 0)) < now:
                f.unlink(missing_ok=True)

    def issue(self, action: str, target: str, ttl_s: int = 900) -> str:
        self.dir.mkdir(parents=True, exist_ok=True)
        self._sweep()
        token = secrets.token_urlsafe(24)
        record = {"action": action, "target": target, "expires_at": time.time() + ttl_s}
        (self.dir / f"{self._hash(token)}.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        return token

    def consume(self, action: str, target: str, token: str) -> bool:
        self._sweep()
        if not token:
            return False
        path = self.dir / f"{self._hash(token)}.json"
        if not path.is_file():
            return False
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        path.unlink(missing_ok=True)  # single-use: gone whether or not it matches
        if record.get("action") != action or record.get("target") != target:
            return False
        if float(record.get("expires_at", 0)) < time.time():
            return False
        return True


class GatedAction:
    def __init__(
        self, name: str, enabled: bool, audit: AuditLog, token_store: TokenStore
    ) -> None:
        self.name = name
        self.enabled = enabled
        self.audit = audit
        self.token_store = token_store

    def _authorize(self, target: str, token: str | None) -> None:
        if not self.enabled:
            raise GateDenied(
                f"Action '{self.name}' is disabled. Set the platform write flag to enable it."
            )
        if not token or not self.token_store.consume(self.name, target, token):
            raise GateDenied(
                f"Action '{self.name}' requires a fresh, valid confirmation token."
            )

    def execute(
        self, *, target: str, actor: str, token: str | None, run: Callable[[], Any]
    ) -> Any:
        self._authorize(target, token)
        result = run()
        self.audit.record(self.name, target, actor, token or "")
        return result

    async def execute_async(
        self,
        *,
        target: str,
        actor: str,
        token: str | None,
        run: Callable[[], Awaitable[Any]],
    ) -> Any:
        self._authorize(target, token)
        result = await run()
        self.audit.record(self.name, target, actor, token or "")
        return result
