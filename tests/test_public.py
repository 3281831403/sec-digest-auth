"""Public smoke tests for Digest authentication handling."""

from __future__ import annotations

from digestauth import (
    build_authorization,
    parse_authorization,
    parse_challenge,
    verify,
)

CHALLENGE = (
    'Digest realm="testrealm@host.com", qop="auth,auth-int", '
    'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
    'opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=MD5'
)

AUTHORIZATION = (
    'Digest username="Mufasa", realm="testrealm@host.com", '
    'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", '
    'qop=auth, nc=00000001, cnonce="0a4f113b", '
    'response="6629fae49393a05397450978507c4ef1", '
    'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
)

NONCE = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
OPAQUE = "5ccc069c403ebaf9f0171e9517f40e41"
PASSWORD = "Circle Of Life"


def _store(**overrides):
    entry = {"expires_in": 60, "opaque": OPAQUE}
    entry.update(overrides)
    return {NONCE: entry}


def _passwords(name):
    return {"Mufasa": PASSWORD}.get(name)


def test_challenge_fields_are_read_from_the_field_value() -> None:
    challenge = parse_challenge(CHALLENGE)
    assert challenge["realm"] == "testrealm@host.com"
    assert challenge["nonce"] == NONCE
    assert challenge["qop"] == ["auth", "auth-int"]
    assert challenge["opaque"] == OPAQUE
    assert challenge["stale"] is False


def test_authorization_response_follows_the_credentials() -> None:
    header = build_authorization(
        "Mufasa",
        PASSWORD,
        "GET",
        "/dir/index.html",
        parse_challenge(CHALLENGE),
        nc="00000001",
        cnonce="0a4f113b",
    )
    assert 'username="Mufasa"' in header
    assert "qop=auth" in header
    assert "nc=00000001" in header
    assert 'nc="' not in header
    assert 'response="6629fae49393a05397450978507c4ef1"' in header


def test_authorization_fields_are_split_into_names() -> None:
    auth = parse_authorization(AUTHORIZATION)
    assert auth["username"] == "Mufasa"
    assert auth["realm"] == "testrealm@host.com"
    assert auth["uri"] == "/dir/index.html"
    assert auth["nc"] == "00000001"
    assert auth["algorithm"] == "MD5"


def test_verify_accepts_the_matching_credentials() -> None:
    header = build_authorization(
        "Mufasa",
        PASSWORD,
        "GET",
        "/dir/index.html",
        parse_challenge(CHALLENGE),
        nc="00000001",
        cnonce="0a4f113b",
    )
    result = verify(header, "GET", "/dir/index.html", _passwords, _store())
    assert result["ok"] is True
    assert result["username"] == "Mufasa"


def test_verify_rejects_a_wrong_password() -> None:
    header = build_authorization(
        "Mufasa",
        "not-the-password",
        "GET",
        "/dir/index.html",
        parse_challenge(CHALLENGE),
        nc="00000001",
        cnonce="0a4f113b",
    )
    result = verify(header, "GET", "/dir/index.html", _passwords, _store())
    assert result["ok"] is False
    assert result["reason"] == "bad-response"