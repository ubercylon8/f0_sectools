import pytest
from f0_sectools_core.auth.config import (
    LimaCharlieConfig,
    PlatformConfig,
    ProjectAchillesConfig,
    SentinelConfig,
    TenableConfig,
)


def test_loads_from_env_mapping():
    env = {"DEFENDER_TENANT_ID": "t", "DEFENDER_CLIENT_ID": "c", "DEFENDER_CLIENT_SECRET": "s"}
    cfg = PlatformConfig.from_env("DEFENDER", env=env)
    assert cfg.tenant_id == "t"
    assert cfg.verify_tls is True
    assert cfg.allow_write is False


def test_missing_vars_raises_listing_names():
    with pytest.raises(ValueError) as e:
        PlatformConfig.from_env("ENTRA", env={})
    assert "ENTRA_TENANT_ID" in str(e.value)


def test_allow_write_and_verify_flags():
    env = {
        "X_TENANT_ID": "t",
        "X_CLIENT_ID": "c",
        "X_CLIENT_SECRET": "s",
        "X_VERIFY_TLS": "false",
        "X_ALLOW_WRITE": "true",
    }
    cfg = PlatformConfig.from_env("X", env=env)
    assert cfg.verify_tls is False
    assert cfg.allow_write is True


def test_limacharlie_config_loads():
    env = {"LIMACHARLIE_OID": "org-123", "LIMACHARLIE_API_KEY": "key-abc"}
    cfg = LimaCharlieConfig.from_env(env=env)
    assert cfg.oid == "org-123"
    assert cfg.api_key == "key-abc"
    assert cfg.uid is None
    assert cfg.allow_write is False


def test_limacharlie_config_missing_raises():
    with pytest.raises(ValueError) as e:
        LimaCharlieConfig.from_env(env={"LIMACHARLIE_OID": "x"})
    assert "LIMACHARLIE_API_KEY" in str(e.value)


def test_limacharlie_config_optional_uid_and_write():
    env = {
        "LIMACHARLIE_OID": "o", "LIMACHARLIE_API_KEY": "k",
        "LIMACHARLIE_UID": "u", "LIMACHARLIE_ALLOW_WRITE": "true",
    }
    cfg = LimaCharlieConfig.from_env(env=env)
    assert cfg.uid == "u"
    assert cfg.allow_write is True


def test_projectachilles_config_loads():
    env = {
        "PROJECTACHILLES_BASE_URL": "https://tpsgl.projectachilles.io",
        "PROJECTACHILLES_API_KEY": "pa_abc123",
    }
    cfg = ProjectAchillesConfig.from_env(env=env)
    assert cfg.base_url == "https://tpsgl.projectachilles.io"
    assert cfg.api_key == "pa_abc123"
    assert cfg.verify_tls is True
    assert cfg.allow_write is False


def test_projectachilles_config_missing_raises():
    with pytest.raises(ValueError) as e:
        ProjectAchillesConfig.from_env(env={"PROJECTACHILLES_BASE_URL": "x"})
    assert "PROJECTACHILLES_API_KEY" in str(e.value)


def test_projectachilles_config_strips_trailing_slash():
    env = {
        "PROJECTACHILLES_BASE_URL": "https://tpsgl.projectachilles.io/",
        "PROJECTACHILLES_API_KEY": "pa_x",
        "PROJECTACHILLES_VERIFY_TLS": "false",
    }
    cfg = ProjectAchillesConfig.from_env(env=env)
    assert cfg.base_url == "https://tpsgl.projectachilles.io"
    assert cfg.verify_tls is False


def test_tenable_config_loads():
    env = {
        "TENABLE_ACCESS_KEY": "ak-123",
        "TENABLE_SECRET_KEY": "sk-456",
    }
    cfg = TenableConfig.from_env(env=env)
    assert cfg.access_key == "ak-123"
    assert cfg.secret_key == "sk-456"
    assert cfg.base_url == "https://cloud.tenable.com"  # default
    assert cfg.verify_tls is True


def test_tenable_config_missing_raises():
    with pytest.raises(ValueError, match="TENABLE_SECRET_KEY"):
        TenableConfig.from_env(env={"TENABLE_ACCESS_KEY": "ak-123"})


def test_tenable_config_custom_base_url_strips_slash():
    env = {
        "TENABLE_ACCESS_KEY": "ak-123",
        "TENABLE_SECRET_KEY": "sk-456",
        "TENABLE_BASE_URL": "https://cloud.tenable.eu/",
        "TENABLE_VERIFY_TLS": "false",
    }
    cfg = TenableConfig.from_env(env=env)
    assert cfg.base_url == "https://cloud.tenable.eu"
    assert cfg.verify_tls is False


def test_projectachilles_confirm_mode_defaults_token():
    env = {
        "PROJECTACHILLES_BASE_URL": "https://tpsgl.projectachilles.io",
        "PROJECTACHILLES_API_KEY": "pa_x",
    }
    assert ProjectAchillesConfig.from_env(env=env).confirm_mode == "token"


def test_projectachilles_confirm_mode_chat_parsed():
    env = {
        "PROJECTACHILLES_BASE_URL": "https://tpsgl.projectachilles.io",
        "PROJECTACHILLES_API_KEY": "pa_x",
        "PROJECTACHILLES_CONFIRM_MODE": "chat",
    }
    assert ProjectAchillesConfig.from_env(env=env).confirm_mode == "chat"


def test_projectachilles_confirm_mode_invalid_raises():
    env = {
        "PROJECTACHILLES_BASE_URL": "https://tpsgl.projectachilles.io",
        "PROJECTACHILLES_API_KEY": "pa_x",
        "PROJECTACHILLES_CONFIRM_MODE": "yolo",
    }
    with pytest.raises(ValueError):
        ProjectAchillesConfig.from_env(env=env)


def test_sentinel_config_from_env_minimal():
    cfg = SentinelConfig.from_env(
        env={
            "SENTINEL_TENANT_ID": "t",
            "SENTINEL_CLIENT_ID": "c",
            "SENTINEL_CLIENT_SECRET": "s",
            "SENTINEL_WORKSPACE_ID": "ws-guid",
        }
    )
    assert cfg.workspace_id == "ws-guid"
    assert cfg.retention_days == 30
    assert cfg.has_arm is False


def test_sentinel_config_has_arm_requires_all_three():
    base = {
        "SENTINEL_TENANT_ID": "t",
        "SENTINEL_CLIENT_ID": "c",
        "SENTINEL_CLIENT_SECRET": "s",
        "SENTINEL_WORKSPACE_ID": "w",
    }
    partial = SentinelConfig.from_env(env={**base, "SENTINEL_SUBSCRIPTION_ID": "sub"})
    assert partial.has_arm is False
    full = SentinelConfig.from_env(
        env={
            **base,
            "SENTINEL_SUBSCRIPTION_ID": "sub",
            "SENTINEL_RESOURCE_GROUP": "rg",
            "SENTINEL_WORKSPACE_NAME": "name",
        }
    )
    assert full.has_arm is True


def test_sentinel_config_retention_days_override_and_bad_value():
    base = {
        "SENTINEL_TENANT_ID": "t",
        "SENTINEL_CLIENT_ID": "c",
        "SENTINEL_CLIENT_SECRET": "s",
        "SENTINEL_WORKSPACE_ID": "w",
    }
    cfg_90 = SentinelConfig.from_env(
        env={**base, "SENTINEL_RETENTION_DAYS": "90"}
    )
    assert cfg_90.retention_days == 90
    # A non-numeric value falls back to the default rather than raising: a bad
    # env value must not take the whole server down.
    cfg_ninety = SentinelConfig.from_env(
        env={**base, "SENTINEL_RETENTION_DAYS": "ninety"}
    )
    assert cfg_ninety.retention_days == 30


def test_sentinel_config_missing_workspace_id_raises():
    with pytest.raises(ValueError, match="SENTINEL_WORKSPACE_ID"):
        SentinelConfig.from_env(
            env={
                "SENTINEL_TENANT_ID": "t",
                "SENTINEL_CLIENT_ID": "c",
                "SENTINEL_CLIENT_SECRET": "s",
            }
        )
