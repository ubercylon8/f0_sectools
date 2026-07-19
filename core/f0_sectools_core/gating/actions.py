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
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any


def gating_dir() -> Path:
    """Fixed cross-process gating-state root — servers and the operator CLI
    must agree on it regardless of their working directories."""
    env = os.environ.get("F0_GATING_DIR")
    return Path(env).expanduser() if env else Path.home() / ".f0sectools" / "gating"


class GateDenied(Exception):
    """Raised when a gated action is attempted without the flag or a valid token."""


class AuditLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path).expanduser() if path else gating_dir() / "audit.log"

    def record(
        self,
        action: str,
        target: str,
        actor: str,
        token: str,
        method: str = "token",
        ref: str | None = None,
    ) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if ref is not None:
            token_ref = ref
        else:
            token_ref = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else ""
        entry = {
            "action": action,
            "target": target,
            "actor": actor,
            "method": method,
            "token_ref": token_ref,
        }
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
        self.dir = Path(dir).expanduser() if dir else gating_dir() / "tokens"

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
        try:
            path.unlink()  # atomic claim: exactly one concurrent caller wins
        except FileNotFoundError:
            return False
        if record.get("action") != action or record.get("target") != target:
            return False
        if float(record.get("expires_at", 0)) < time.time():
            return False
        return True


class ApprovalStore:
    """Pending requests + human-granted pre-approvals, keyed by (action, target).

    Requests (written by servers when they return an intent) are display data
    for the operator watcher — NEVER authorization. Approvals are written only
    by the human-side CLI (scripts/confirm_action.py); consuming one is
    single-use with the same unlink-before-validate discipline as TokenStore,
    so concurrent callers cannot both win.
    """

    def __init__(self, dir: str | None = None) -> None:
        root = Path(dir).expanduser() if dir else gating_dir()
        self.requests = root / "requests"
        self.approvals = root / "approvals"

    @staticmethod
    def _key(action: str, target: str) -> str:
        return hashlib.sha256(f"{action}|{target}".encode()).hexdigest()

    @staticmethod
    def _sweep(dir_: Path) -> None:
        if not dir_.is_dir():
            return
        now = time.time()
        for f in dir_.glob("*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if float(rec.get("expires_at", 0)) < now:
                f.unlink(missing_ok=True)

    def record_request(self, action: str, target: str, ttl_s: int = 900) -> None:
        self.requests.mkdir(parents=True, exist_ok=True)
        self._sweep(self.requests)
        record = {
            "action": action,
            "target": target,
            "requested_at": time.time(),
            "expires_at": time.time() + ttl_s,
        }
        (self.requests / f"{self._key(action, target)}.json").write_text(
            json.dumps(record), encoding="utf-8"
        )

    def list_pending(self) -> list[dict[str, Any]]:
        self._sweep(self.requests)
        out: list[dict[str, Any]] = []
        if self.requests.is_dir():
            for f in sorted(self.requests.glob("*.json")):
                try:
                    out.append(json.loads(f.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    continue
        return out

    def approve(self, action: str, target: str, ttl_s: int = 900) -> None:
        self.approvals.mkdir(parents=True, exist_ok=True)
        self._sweep(self.approvals)
        record = {"action": action, "target": target, "expires_at": time.time() + ttl_s}
        (self.approvals / f"{self._key(action, target)}.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        (self.requests / f"{self._key(action, target)}.json").unlink(missing_ok=True)

    def deny(self, action: str, target: str) -> None:
        (self.requests / f"{self._key(action, target)}.json").unlink(missing_ok=True)

    def has_approval(self, action: str, target: str) -> bool:
        self._sweep(self.approvals)
        return (self.approvals / f"{self._key(action, target)}.json").is_file()

    def consume(self, action: str, target: str) -> bool:
        self._sweep(self.approvals)
        path = self.approvals / f"{self._key(action, target)}.json"
        if not path.is_file():
            return False
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        try:
            path.unlink()  # atomic claim: exactly one concurrent caller wins
        except FileNotFoundError:
            return False
        if record.get("action") != action or record.get("target") != target:
            return False
        if float(record.get("expires_at", 0)) < time.time():
            return False
        return True


class GatedAction:
    def __init__(
        self,
        name: str,
        enabled: bool,
        audit: AuditLog,
        token_store: TokenStore,
        approvals: ApprovalStore | None = None,
        confirm_mode: str = "token",
    ) -> None:
        self.name = name
        self.enabled = enabled
        self.audit = audit
        self.token_store = token_store
        self.approvals = approvals if approvals is not None else ApprovalStore()
        self.confirm_mode = confirm_mode

    def has_approval(self, target: str) -> bool:
        """Non-consuming peek — lets a tool decide intent vs execute."""
        return self.approvals.has_approval(self.name, target)

    def record_request(self, target: str) -> None:
        """Publish a pending request for the operator watcher (display only)."""
        self.approvals.record_request(self.name, target)

    def _authorize(self, target: str, token: str | None) -> str:
        if not self.enabled:
            raise GateDenied(
                f"Action '{self.name}' is disabled. Set the platform write flag to enable it."
            )
        if self.confirm_mode == "chat" and token is not None and token == target:
            # Chat-confirm: the operator replied "approved" and the model
            # echoed the exact target back. Not forge-resistant (opt-in only).
            return "chat-confirm"
        if token:
            if self.token_store.consume(self.name, target, token):
                return "token"
            raise GateDenied(
                f"Action '{self.name}' requires a fresh, valid confirmation token."
            )
        if self.approvals.consume(self.name, target):
            return "approval"
        raise GateDenied(
            f"Action '{self.name}' requires a watcher approval "
            f"(confirm_action.py --watch) or a confirmation token."
        )

    def _audit(self, target: str, actor: str, token: str | None, method: str) -> None:
        ref = (
            ApprovalStore._key(self.name, target)[:16]
            if method in ("approval", "chat-confirm")
            else None
        )
        self.audit.record(self.name, target, actor, token or "", method=method, ref=ref)

    def execute(
        self, *, target: str, actor: str, token: str | None, run: Callable[[], Any]
    ) -> Any:
        method = self._authorize(target, token)
        result = run()
        self._audit(target, actor, token, method)
        return result

    async def execute_async(
        self,
        *,
        target: str,
        actor: str,
        token: str | None,
        run: Callable[[], Awaitable[Any]],
    ) -> Any:
        method = self._authorize(target, token)
        result = await run()
        self._audit(target, actor, token, method)
        return result
