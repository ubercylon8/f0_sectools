import pytest
from f0_sectools_core.auth.config import PlatformConfig


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
