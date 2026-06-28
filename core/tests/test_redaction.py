from f0_sectools_core.redaction.redact import redact_obj, redact_text


def test_redacts_bearer_token():
    assert "«redacted»" in redact_text("Authorization: Bearer abc.DEF-123_xyz.longtokenvalue")


def test_redacts_secret_keyed_values():
    out = redact_obj({"client_secret": "s3cr3t-value-here", "host": "web-01"})
    assert out["client_secret"] == "«redacted»"
    assert out["host"] == "web-01"


def test_redacts_nested():
    out = redact_obj({"creds": {"password": "hunter2hunter2"}, "items": ["ok"]})
    assert out["creds"]["password"] == "«redacted»"
    assert out["items"] == ["ok"]
