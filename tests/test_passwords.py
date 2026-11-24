"""Tests for password generation and Argon2 hashing."""

from __future__ import annotations

import uuid

from argon2 import PasswordHasher

from jwks_server import passwords


def test_generated_password_is_uuid4() -> None:
    password = passwords.generate_password()
    assert uuid.UUID(password).version == 4


def test_generated_passwords_are_unique() -> None:
    assert len({passwords.generate_password() for _ in range(100)}) == 100


def test_hash_uses_argon2id_with_configured_settings() -> None:
    password_hash = passwords.hash_password("secret")
    assert password_hash.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert "secret" not in password_hash


def test_hashes_are_salted() -> None:
    assert passwords.hash_password("secret") != passwords.hash_password("secret")


def test_verify_accepts_correct_password() -> None:
    assert passwords.verify_password(passwords.hash_password("secret"), "secret")


def test_verify_rejects_wrong_password() -> None:
    assert not passwords.verify_password(passwords.hash_password("secret"), "guess")


def test_verify_rejects_malformed_hash() -> None:
    assert not passwords.verify_password("not-a-hash", "secret")


def test_needs_rehash_detects_old_settings() -> None:
    old_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("secret")
    assert passwords.needs_rehash(old_hash)
    assert not passwords.needs_rehash(passwords.hash_password("secret"))
