"""Strip secrets/PII from all tool output, including error paths.

Every value returned to the agent passes through here. Redaction is centralized
so the "secrets never reach the model" guarantee is enforced in one place.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .patterns import REDACTED, SECRET_KEY_HINTS, SECRET_VALUE_PATTERNS

if TYPE_CHECKING:
    from f0_sectools_core.schema.findings import Finding


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


def redact_finding(finding: Finding) -> Finding:
    """Redact a Finding's full structured payload; returns a new Finding.

    Applies the generic key/value redaction (``redact_obj``) and then additionally
    blanks any evidence value whose *key* hints at a secret. Evidence is a flat
    ``{key, value}`` list, so ``redact_obj``'s dict-key check never sees the
    evidence key name (it is stored as a value under the literal ``"key"``); this
    pass closes that gap. This is what every server's ``_render`` calls before a
    finding leaves the process, and it is also what a generated report (e.g.
    ``core/reports/emit.py``) uses on the same findings — one entry point, same
    guarantee on both paths. Centralized here per Critical Rule 3/6 — never
    reimplement per caller.
    """
    from f0_sectools_core.schema.findings import Finding as _Finding

    data = redact_obj(finding.model_dump())
    for ev in data.get("evidence", []):
        if isinstance(ev, dict) and _key_is_secret(str(ev.get("key", ""))):
            ev["value"] = REDACTED
    return _Finding.model_validate(data)
