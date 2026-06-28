"""Per-platform credential loading. Secrets never leave this layer or get logged.

Each platform reads its own ``.env.<platform>`` via a distinct prefix (e.g.
``DEFENDER``, ``ENTRA``), so credentials are isolated per platform with no
cross-bleed.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

_TRUE = {"1", "true", "yes", "on"}


@dataclass
class PlatformConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    verify_tls: bool = True
    allow_write: bool = False
    extra: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, prefix: str, env: Mapping[str, str] | None = None) -> PlatformConfig:
        env = env if env is not None else os.environ
        required = {k: f"{prefix}_{k.upper()}" for k in ("tenant_id", "client_id", "client_secret")}
        missing = [name for name in required.values() if not env.get(name)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
        verify = env.get(f"{prefix}_VERIFY_TLS", "true").strip().lower() in _TRUE
        allow_write = env.get(f"{prefix}_ALLOW_WRITE", "false").strip().lower() in _TRUE
        return cls(
            tenant_id=env[required["tenant_id"]],
            client_id=env[required["client_id"]],
            client_secret=env[required["client_secret"]],
            verify_tls=verify,
            allow_write=allow_write,
        )
