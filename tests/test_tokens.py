"""Tests for JWT issuing."""

from __future__ import annotations

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from jwks_server.keystore import SigningKey
from jwks_server.tokens import issue_token

NOW = 1_700_000_000


def make_key(expires_at: int) -> SigningKey:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return SigningKey(kid=7, private_key=private_key, expires_at=expires_at)


def test_token_is_signed_and_has_kid() -> None:
    key = make_key(NOW + 3600)
    token = issue_token(key, "alice", 900, now=NOW)
    assert jwt.get_unverified_header(token)["kid"] == "7"
    claims = jwt.decode(
        token,
        key.private_key.public_key(),
        algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert claims == {"sub": "alice", "iat": NOW, "exp": NOW + 900}


def test_token_never_outlives_its_key() -> None:
    token = issue_token(make_key(NOW + 60), "alice", 900, now=NOW)
    assert jwt.decode(token, options={"verify_signature": False})["exp"] == NOW + 60


def test_expired_key_gives_expired_token() -> None:
    token = issue_token(make_key(NOW - 3600), "alice", 900, now=NOW)
    assert jwt.decode(token, options={"verify_signature": False})["exp"] < NOW


def test_uses_current_time_by_default() -> None:
    key = make_key(4_000_000_000)
    claims = jwt.decode(issue_token(key, "alice", 900), options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 900
