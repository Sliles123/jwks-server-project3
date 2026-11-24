"""AES-256-GCM encryption for private keys at rest."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_SIZE = 32  # bytes, so AES-256
NONCE_SIZE = 12  # 96-bit nonce, the size GCM is designed around
_HKDF_INFO = b"jwks-server/private-key-encryption/v1"


class DecryptionError(Exception):
    """Raised when a ciphertext fails authentication or is malformed."""


class KeyCipher:
    """Encrypts and decrypts private key material with AES-256-GCM.

    Every call to encrypt() uses a fresh random nonce (the IV). The nonce is
    not secret, so it is stored in front of the ciphertext in the same column:

        blob = nonce (12 bytes) || ciphertext || GCM tag (16 bytes)

    Keeping it in one column leaves the keys table at its original
    (kid, key, exp) schema, which the gradebot reads column for column.
    GCM is authenticated, so a modified blob fails to decrypt instead of
    producing a corrupted key.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_SIZE:
            raise ValueError(f"AES-256 requires a {KEY_SIZE}-byte key")
        self._aesgcm = AESGCM(key)

    @classmethod
    def from_secret(cls, secret: str) -> KeyCipher:
        """Derive a 256-bit AES key from the NOT_MY_KEY secret with HKDF-SHA256.

        HKDF turns a secret of any length into exactly 32 bytes, instead of
        padding or truncating the raw string.
        """
        if not secret:
            raise ValueError("encryption secret must not be empty")
        hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None, info=_HKDF_INFO)
        return cls(hkdf.derive(secret.encode("utf-8")))

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
        """Encrypt plaintext and return nonce || ciphertext || tag."""
        nonce = os.urandom(NONCE_SIZE)
        return nonce + self._aesgcm.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, blob: bytes, associated_data: bytes | None = None) -> bytes:
        """Reverse encrypt(). Raises DecryptionError if the blob was altered."""
        if len(blob) <= NONCE_SIZE:
            raise DecryptionError("ciphertext is too short")
        nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
        try:
            return self._aesgcm.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag as exc:
            raise DecryptionError("ciphertext failed authentication") from exc
