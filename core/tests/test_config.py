import pytest
from f0_sectools_core.auth.config import LimaCharlieConfig, PlatformConfig


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
