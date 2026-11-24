"""Tests for AES-GCM key encryption."""

from __future__ import annotations

import pytest

from jwks_server.crypto import KEY_SIZE, NONCE_SIZE, DecryptionError, KeyCipher

from .conftest import TEST_SECRET

PEM = b"-----BEGIN RSA PRIVATE KEY-----\nnot really a key\n-----END RSA PRIVATE KEY-----\n"


def test_round_trip() -> None:
    cipher = KeyCipher.from_secret(TEST_SECRET)
    assert cipher.decrypt(cipher.encrypt(PEM)) == PEM


def test_ciphertext_hides_plaintext() -> None:
    blob = KeyCipher.from_secret(TEST_SECRET).encrypt(PEM)
    assert b"BEGIN" not in blob
    assert not blob.startswith(b"-----")


def test_each_encryption_uses_a_fresh_nonce() -> None:
    cipher = KeyCipher.from_secret(TEST_SECRET)
    first, second = cipher.encrypt(PEM), cipher.encrypt(PEM)
    assert first != second
    assert first[:NONCE_SIZE] != second[:NONCE_SIZE]


def test_same_secret_derives_same_key() -> None:
    blob = KeyCipher.from_secret(TEST_SECRET).encrypt(PEM)
    assert KeyCipher.from_secret(TEST_SECRET).decrypt(blob) == PEM


def test_wrong_secret_cannot_decrypt() -> None:
    blob = KeyCipher.from_secret(TEST_SECRET).encrypt(PEM)
    with pytest.raises(DecryptionError):
        KeyCipher.from_secret(TEST_SECRET + "x").decrypt(blob)


def test_tampered_ciphertext_is_rejected() -> None:
    cipher = KeyCipher.from_secret(TEST_SECRET)
    blob = bytearray(cipher.encrypt(PEM))
    blob[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        cipher.decrypt(bytes(blob))


def test_associated_data_must_match() -> None:
    cipher = KeyCipher.from_secret(TEST_SECRET)
    blob = cipher.encrypt(PEM, b"keys.exp=1")
    assert cipher.decrypt(blob, b"keys.exp=1") == PEM
    with pytest.raises(DecryptionError):
        cipher.decrypt(blob, b"keys.exp=2")


def test_truncated_blob_is_rejected() -> None:
    with pytest.raises(DecryptionError):
        KeyCipher.from_secret(TEST_SECRET).decrypt(b"short")


def test_key_must_be_32_bytes() -> None:
    with pytest.raises(ValueError):
        KeyCipher(b"x" * (KEY_SIZE - 1))


def test_empty_secret_is_rejected() -> None:
    with pytest.raises(ValueError):
        KeyCipher.from_secret("")
