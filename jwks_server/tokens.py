"""JWT issuing."""

from __future__ import annotations

import time

import jwt

from .keystore import JWT_ALGORITHM, SigningKey


def issue_token(
    signing_key: SigningKey,
    subject: str,
    lifetime_seconds: int,
    now: int | None = None,
) -> str:
    """Sign a JWT for `subject` with the given key.

    The token never outlives its key: once a key expires it leaves the JWKS,
    so a token that claimed to be valid past that point could not be
    verified anyway. With an expired key this gives an already-expired token,
    which is what /auth?expired=true is supposed to return.
    """
    issued_at = int(time.time()) if now is None else now
    expires_at = min(issued_at + lifetime_seconds, signing_key.expires_at)
    claims = {"sub": subject, "iat": issued_at, "exp": expires_at}
    return jwt.encode(
        claims,
        signing_key.private_key,
        algorithm=JWT_ALGORITHM,
        headers={"kid": str(signing_key.kid)},
    )
