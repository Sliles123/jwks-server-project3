"""RSA signing keys, stored AES-encrypted in the keys table."""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from .config import ENCRYPTION_KEY_ENV
from .crypto import DecryptionError, KeyCipher

logger = logging.getLogger(__name__)

JWT_ALGORITHM = "RS256"
RSA_KEY_BITS = 2048
RSA_PUBLIC_EXPONENT = 65537
_PEM_MARKER = b"-----BEGIN"


@dataclass(frozen=True)
class SigningKey:
    """A decrypted private key with its key id and expiry (Unix time)."""

    kid: int
    private_key: rsa.RSAPrivateKey
    expires_at: int


class KeyStore:
    """Creates, encrypts, decrypts, and publishes the server's RSA key pairs.

    Private keys are only ever written to the database encrypted. Decrypted
    keys are cached in memory by (kid, exp) because parsing an RSA key takes
    around 60 ms, and /auth has to stay fast enough for a 10 req/s limit.
    The database stays the source of truth for which keys exist.
    """

    def __init__(
        self,
        cipher: KeyCipher,
        key_lifetime_seconds: int = 3600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._cipher = cipher
        self._lifetime = key_lifetime_seconds
        self._clock = clock
        self._cache: dict[tuple[int, int], rsa.RSAPrivateKey] = {}
        self._unreadable: set[int] = set()
        self._lock = threading.Lock()

    def initialize(self, conn: sqlite3.Connection) -> None:
        """Encrypt leftover plaintext keys, then make sure a valid and an expired key exist."""
        migrated = self.encrypt_plaintext_keys(conn)
        if migrated:
            logger.info("Encrypted %d plaintext private key(s) from an older database", migrated)
        self.get_signing_key(conn, expired=False)
        self.get_signing_key(conn, expired=True)

    def encrypt_plaintext_keys(self, conn: sqlite3.Connection) -> int:
        """Encrypt rows that still hold a plaintext PEM, e.g. a Project 2 database."""
        updates = []
        for row in conn.execute("SELECT kid, key, exp FROM keys").fetchall():
            raw = _as_bytes(row["key"])
            if raw.lstrip().startswith(_PEM_MARKER):
                updates.append((self._cipher.encrypt(raw.strip(), _aad(row["exp"])), row["kid"]))
        if updates:
            with conn:
                conn.executemany("UPDATE keys SET key = ? WHERE kid = ?", updates)
        return len(updates)

    def get_signing_key(self, conn: sqlite3.Connection, expired: bool = False) -> SigningKey:
        """Return the newest usable valid (or expired) key, creating one if none exists."""
        now = int(self._clock())
        if expired:
            query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC"
        else:
            query = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC"
        for row in conn.execute(query, (now,)).fetchall():
            signing_key = self._load(row)
            if signing_key is not None:
                return signing_key
        offset = -self._lifetime if expired else self._lifetime
        return self._create(conn, now + offset)

    def jwks(self, conn: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
        """Return the public JWKS. Only keys that have not expired are included."""
        now = int(self._clock())
        rows = conn.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid", (now,)).fetchall()
        keys = []
        for row in rows:
            signing_key = self._load(row)
            if signing_key is None:
                continue
            jwk = RSAAlgorithm.to_jwk(signing_key.private_key.public_key(), as_dict=True)
            # RFC 7517 4.3: "use" and "key_ops" should not both be present.
            jwk.pop("key_ops", None)
            jwk.update({"kid": str(signing_key.kid), "alg": JWT_ALGORITHM, "use": "sig"})
            keys.append(jwk)
        return {"keys": keys}

    def _create(self, conn: sqlite3.Connection, expires_at: int) -> SigningKey:
        """Generate a key pair, store it encrypted, and return it."""
        private_key = rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_BITS)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encrypted = self._cipher.encrypt(pem, _aad(expires_at))
        with conn:
            cursor = conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted, expires_at))
        kid = int(cursor.lastrowid)
        with self._lock:
            self._cache[(kid, expires_at)] = private_key
        state = "expired" if expires_at <= self._clock() else "valid"
        logger.info("Generated %s signing key kid=%d", state, kid)
        return SigningKey(kid, private_key, expires_at)

    def _load(self, row: sqlite3.Row) -> SigningKey | None:
        """Return the decrypted key for a row, or None if it cannot be used."""
        kid, expires_at = int(row["kid"]), int(row["exp"])
        with self._lock:
            private_key = self._cache.get((kid, expires_at))
        if private_key is None:
            private_key = self._decrypt(kid, _as_bytes(row["key"]), expires_at)
            if private_key is None:
                return None
            with self._lock:
                self._cache[(kid, expires_at)] = private_key
        return SigningKey(kid, private_key, expires_at)

    def _decrypt(self, kid: int, blob: bytes, expires_at: int) -> rsa.RSAPrivateKey | None:
        try:
            pem = self._cipher.decrypt(blob, _aad(expires_at))
            private_key = serialization.load_pem_private_key(pem, password=None)
        except (DecryptionError, ValueError, TypeError, UnsupportedAlgorithm):
            self._warn_unreadable(kid)
            return None
        if not isinstance(private_key, rsa.RSAPrivateKey):
            self._warn_unreadable(kid)
            return None
        return private_key

    def _warn_unreadable(self, kid: int) -> None:
        """Log once per key, so a bad row does not flood the log on every request."""
        with self._lock:
            if kid in self._unreadable:
                return
            self._unreadable.add(kid)
        logger.warning(
            "Skipping key kid=%d: it cannot be decrypted with the current %s",
            kid,
            ENCRYPTION_KEY_ENV,
        )


def _aad(expires_at: int) -> bytes:
    """Associated data that binds a ciphertext to its expiry.

    Changing a key's exp in the database makes it fail to decrypt, so an
    expired key cannot be brought back by editing one column.
    """
    return f"keys.exp={expires_at}".encode("ascii")


def _as_bytes(value: bytes | str) -> bytes:
    """Older databases may store the key column as TEXT instead of BLOB."""
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)
