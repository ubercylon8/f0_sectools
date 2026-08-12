"""Per-platform credential loading. Secrets never leave this layer or get logged.

Each platform reads its own ``.env.<platform>`` via a distinct prefix (e.g.
``DEFENDER``, ``ENTRA``), so credentials are isolated per platform with no
cross-bleed.
"""
from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from .env import find_platform_env

_TRUE = {"1", "true", "yes", "on"}


def _require_env(prefix: str, names: Iterable[str], env: Mapping[str, str]) -> None:
    """Raise if any required variable is unset, saying where credentials were looked for.

    The variable names alone are a dead end: the usual cause is not a missing
    key but a credential file that was never located, which looks identical
    from the caller's side. Naming the file and its search result turns a
    guessing game into a one-line fix. Values are never included.
    """
    missing = [name for name in names if not env.get(name)]
    if not missing:
        return
    platform = prefix.lower()
    found = find_platform_env(platform)
    where = (
        f"found .env.{platform} in {found.parent} - add the missing keys there"
        if found
        else (
            f"no .env.{platform} was found in the working directory, its parents, "
            "or the installed package's checkout - create one in the repo root "
            "or point F0_SECTOOLS_ENV_DIR at it"
        )
    )
    raise ValueError(f"Missing required environment variables: {', '.join(missing)} ({where})")


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
        _require_env(prefix, required.values(), env)
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
        _require_env(prefix, required.values(), env)
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
    confirm_mode: str = "token"

    @classmethod
    def from_env(
        cls, prefix: str = "PROJECTACHILLES", env: Mapping[str, str] | None = None
    ) -> ProjectAchillesConfig:
        env = env if env is not None else os.environ
        required = {"base_url": f"{prefix}_BASE_URL", "api_key": f"{prefix}_API_KEY"}
        _require_env(prefix, required.values(), env)
        verify = env.get(f"{prefix}_VERIFY_TLS", "true").strip().lower() in _TRUE
        allow_write = env.get(f"{prefix}_ALLOW_WRITE", "false").strip().lower() in _TRUE
        confirm_mode = env.get(f"{prefix}_CONFIRM_MODE", "token").strip().lower()
        if confirm_mode not in ("token", "chat"):
            raise ValueError(
                f"{prefix}_CONFIRM_MODE must be 'token' or 'chat', got '{confirm_mode}'"
            )
        return cls(
            base_url=env[required["base_url"]].rstrip("/"),
            api_key=env[required["api_key"]],
            verify_tls=verify,
            allow_write=allow_write,
            confirm_mode=confirm_mode,
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
        _require_env(prefix, required.values(), env)
        verify = env.get(f"{prefix}_VERIFY_TLS", "true").strip().lower() in _TRUE
        base_url = env.get(f"{prefix}_BASE_URL", "https://cloud.tenable.com").rstrip("/")
        return cls(
            access_key=env[required["access_key"]],
            secret_key=env[required["secret_key"]],
            base_url=base_url,
            verify_tls=verify,
        )


@dataclass
class SentinelConfig:
    """Microsoft Sentinel credentials: an Entra app plus workspace coordinates.

    Two API surfaces with different RBAC. The logs half (KQL) needs only
    ``workspace_id`` and the Log Analytics Reader role. The objects half
    (analytics rules, watchlists) needs the ARM triple and Microsoft Sentinel
    Reader; when it is absent the server degrades gracefully rather than
    failing, so a logs-only deployment is a supported configuration.

    Loaded from .env.sentinel. Secrets never leave this layer or get logged.
    """

    tenant_id: str
    client_id: str
    client_secret: str
    workspace_id: str
    subscription_id: str | None = None
    resource_group: str | None = None
    workspace_name: str | None = None
    retention_days: int = 30
    verify_tls: bool = True

    @property
    def has_arm(self) -> bool:
        """True when all three ARM coordinates are present."""
        return bool(self.subscription_id and self.resource_group and self.workspace_name)

    @classmethod
    def from_env(
        cls, prefix: str = "SENTINEL", env: Mapping[str, str] | None = None
    ) -> SentinelConfig:
        env = env if env is not None else os.environ
        required = {
            k: f"{prefix}_{k.upper()}"
            for k in ("tenant_id", "client_id", "client_secret", "workspace_id")
        }
        _require_env(prefix, required.values(), env)
        try:
            retention = int(env.get(f"{prefix}_RETENTION_DAYS", "30"))
        except ValueError:
            retention = 30
        if retention < 1:
            retention = 30
        return cls(
            tenant_id=env[required["tenant_id"]],
            client_id=env[required["client_id"]],
            client_secret=env[required["client_secret"]],
            workspace_id=env[required["workspace_id"]],
            subscription_id=env.get(f"{prefix}_SUBSCRIPTION_ID") or None,
            resource_group=env.get(f"{prefix}_RESOURCE_GROUP") or None,
            workspace_name=env.get(f"{prefix}_WORKSPACE_NAME") or None,
            retention_days=retention,
            verify_tls=env.get(f"{prefix}_VERIFY_TLS", "true").strip().lower() in _TRUE,
        )
