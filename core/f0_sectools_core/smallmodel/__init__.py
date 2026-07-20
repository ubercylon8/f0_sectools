"""Helpers for small-model-safe tools: flat-arg builders, enum guards, arg validation.

Input-validation predicates shared by every server so read/write guards stay
consistent (Critical Rule 6 — validation logic lives in core, not per-server):

- ``scope_ok`` — STRICT bound for a gated-write / scoping identifier
  (host/tag/test scope, bulk-cancel search). Bounded charset, 1-128 chars.
- ``search_ok`` — PERMISSIVE bound for a read-side free-text search term.
  Length + no control characters only; legit multi-word / dotted / id / paren
  searches pass. This is context-window / hygiene bounding, not injection
  defense (httpx URL-encodes params).
"""
from __future__ import annotations

import re

# Strict scope/identifier charset: letters, digits, space, and . _ - : @ /
_SCOPE_RE = re.compile(r"^[A-Za-z0-9 ._:@/\-]{1,128}$")

_MAX_SEARCH = 128


def scope_ok(value: str) -> bool:
    """True if ``value`` is a valid strict scope identifier (1-128 chars of the
    bounded charset). Used for gated-write targets and test/tag/host scoping."""
    return bool(_SCOPE_RE.match(value))


def search_ok(value: str) -> bool:
    """True if ``value`` is an acceptable read-side search term: at most 128
    chars and no control characters. Permissive on purpose — legit searches
    (spaces, dots, parentheses, ids like ``T1550.002``) pass."""
    return len(value) <= _MAX_SEARCH and all(ord(c) >= 0x20 for c in value)
