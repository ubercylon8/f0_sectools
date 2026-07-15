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


def test_redacts_additional_secret_key_hints():
    # Low-entropy secrets under these keys wouldn't match a value pattern, so the
    # key-hint pass must catch them (private_key/credential/cookie/session_id).
    out = redact_obj({
        "private_key": "abc", "credentials": "u:p", "cookie": "sid=1",
        "session_id": "xyz", "host": "web-01",
    })
    assert out["private_key"] == "«redacted»"
    assert out["credentials"] == "«redacted»"
    assert out["cookie"] == "«redacted»"
    assert out["session_id"] == "«redacted»"
    assert out["host"] == "web-01"


def test_redacts_camelcase_secret_keys():
    # Underscore normalization makes multi-word hints catch camelCase too — Graph
    # servers (Entra/Defender/Intune) emit sessionId/privateKey/clientSecret.
    out = redact_obj({
        "sessionId": "x", "privateKey": "y", "clientSecret": "z", "host": "web-01",
    })
    assert out["sessionId"] == "«redacted»"
    assert out["privateKey"] == "«redacted»"
    assert out["clientSecret"] == "«redacted»"
    assert out["host"] == "web-01"
