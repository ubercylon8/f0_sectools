"""Strip secrets/PII from all tool output, including error paths.

Every value returned to the agent passes through here. Redaction is centralized
so the "secrets never reach the model" guarantee is enforced in one place.
"""
from __future__ import annotations

from typing import Any

from .patterns import REDACTED, SECRET_KEY_HINTS, SECRET_VALUE_PATTERNS


def redact_text(text: str) -> str:
    out = text
    for pat in SECRET_VALUE_PATTERNS:
        out = pat.sub(REDACTED, out)
    return out


def _key_is_secret(key: str) -> bool:
    # Normalize underscores so multi-word hints match both snake_case and camelCase
    # (e.g. `session_id` catches `SESSION_ID` and `sessionId`; Graph servers emit the
    # latter, LimaCharlie the former).
    k = key.lower().replace("_", "")
    return any(hint.replace("_", "") in k for hint in SECRET_KEY_HINTS)


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: (REDACTED if _key_is_secret(str(k)) else redact_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj
