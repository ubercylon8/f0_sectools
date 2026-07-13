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


@dataclass
class LimaCharlieConfig:
    """LimaCharlie credentials (org ID + API key; optional user ID).

    Loaded from .env.limacharlie. Secrets never leave this layer or get logged.
    """

    oid: str
    api_key: str
    uid: str | None = None
    allow_write: bool = False

    @classmethod
    def from_env(
        cls, prefix: str = "LIMACHARLIE", env: Mapping[str, str] | None = None
    ) -> LimaCharlieConfig:
        env = env if env is not None else os.environ
        required = {"oid": f"{prefix}_OID", "api_key": f"{prefix}_API_KEY"}
        missing = [name for name in required.values() if not env.get(name)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
        allow_write = env.get(f"{prefix}_ALLOW_WRITE", "false").strip().lower() in _TRUE
        return cls(
            oid=env[required["oid"]],
            api_key=env[required["api_key"]],
            uid=env.get(f"{prefix}_UID") or None,
            allow_write=allow_write,
        )


@dataclass
class ProjectAchillesConfig:
    """ProjectAchilles credentials: instance base URL + a `pa_` API key.

    The org is embedded in the key, so no separate org ID is needed. Loaded from
    .env.projectachilles. Secrets never leave this layer or get logged.
    """

    base_url: str
    api_key: str
    verify_tls: bool = True
    allow_write: bool = False

    @classmethod
    def from_env(
        cls, prefix: str = "PROJECTACHILLES", env: Mapping[str, str] | None = None
    ) -> ProjectAchillesConfig:
        env = env if env is not None else os.environ
        required = {"base_url": f"{prefix}_BASE_URL", "api_key": f"{prefix}_API_KEY"}
        missing = [name for name in required.values() if not env.get(name)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
        verify = env.get(f"{prefix}_VERIFY_TLS", "true").strip().lower() in _TRUE
        allow_write = env.get(f"{prefix}_ALLOW_WRITE", "false").strip().lower() in _TRUE
        return cls(
            base_url=env[required["base_url"]].rstrip("/"),
            api_key=env[required["api_key"]],
            verify_tls=verify,
            allow_write=allow_write,
        )


@dataclass
class TenableConfig:
    """Tenable Vulnerability Management credentials: an access key + secret key.

    Sent as ``X-ApiKeys: accessKey=<>;secretKey=<>``. Read-only server, so there
    is no allow_write flag. Loaded from .env.tenable. Secrets never leave this
    layer or get logged.
    """

    access_key: str
    secret_key: str
    base_url: str = "https://cloud.tenable.com"
    verify_tls: bool = True

    @classmethod
    def from_env(
        cls, prefix: str = "TENABLE", env: Mapping[str, str] | None = None
    ) -> TenableConfig:
        env = env if env is not None else os.environ
        required = {
            "access_key": f"{prefix}_ACCESS_KEY",
            "secret_key": f"{prefix}_SECRET_KEY",
        }
        missing = [name for name in required.values() if not env.get(name)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
        verify = env.get(f"{prefix}_VERIFY_TLS", "true").strip().lower() in _TRUE
        base_url = env.get(f"{prefix}_BASE_URL", "https://cloud.tenable.com").rstrip("/")
        return cls(
            access_key=env[required["access_key"]],
            secret_key=env[required["secret_key"]],
            base_url=base_url,
            verify_tls=verify,
        )
