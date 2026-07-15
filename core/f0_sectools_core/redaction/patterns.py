"""Compiled secret/PII regexes used by the redaction layer."""
import re

REDACTED = "«redacted»"

# Keys whose values are always secrets, matched case-insensitively as substrings.
SECRET_KEY_HINTS = (
    "secret",
    "password",
    "passwd",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "client_secret",
    "private_key",
    "credentials",
    "cookie",
)

# Value patterns that look like secrets/tokens regardless of key.
SECRET_VALUE_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{12,}", re.IGNORECASE),
    re.compile(r"eyJ[A-Za-z0-9._\-]{20,}"),  # JWT
    re.compile(r"[A-Za-z0-9_\-]{32,}\.[A-Za-z0-9_\-]{6,}"),  # client-secret-ish
]
