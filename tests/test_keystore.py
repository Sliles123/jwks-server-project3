"""Tests for encrypted key storage."""

from __future__ import annotations

import logging
import secrets
import sqlite3

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from jwks_server.crypto import KeyCipher
from jwks_server.keystore import KeyStore

from .conftest import TEST_SECRET, FakeClock

LIFETIME = 3600


def make_store(clock: FakeClock, secret: str = TEST_SECRET) -> KeyStore:
    return KeyStore(KeyCipher.from_secret(secret), LIFETIME, clock=clock)


def rsa_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def insert_raw_key(conn: sqlite3.Connection, key: bytes | str, exp: int) -> int:
    with conn:
        cursor = conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, exp))
    return int(cursor.lastrowid)


def stored_keys(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT kid, key, exp FROM keys").fetchall()


def jwks_kids(store: KeyStore, conn: sqlite3.Connection) -> set[str]:
    return {jwk["kid"] for jwk in store.jwks(conn)["keys"]}


def test_initialize_creates_a_valid_and_an_expired_key(
    empty_db: sqlite3.Connection, clock: FakeClock
) -> None:
    make_store(clock).initialize(empty_db)
    exps = sorted(row["exp"] for row in stored_keys(empty_db))
    assert exps == [int(clock()) - LIFETIME, int(clock()) + LIFETIME]


def test_keys_are_encrypted_at_rest(empty_db: sqlite3.Connection, clock: FakeClock) -> None:
    make_store(clock).initialize(empty_db)
    for row in stored_keys(empty_db):
        blob = bytes(row["key"])
        assert not blob.lstrip().startswith(b"-----BEGIN")
        with pytest.raises(ValueError):
            serialization.load_pem_private_key(blob, password=None)


def test_initialize_reuses_existing_keys(empty_db: sqlite3.Connection, clock: FakeClock) -> None:
    make_store(clock).initialize(empty_db)
    make_store(clock).initialize(empty_db)  # e.g. a server restart
    assert len(stored_keys(empty_db)) == 2


def test_jwks_lists_only_unexpired_keys(empty_db: sqlite3.Connection, clock: FakeClock) -> None:
    store = make_store(clock)
    store.initialize(empty_db)
    valid = store.get_signing_key(empty_db)
    expired = store.get_signing_key(empty_db, expired=True)

    jwks = store.jwks(empty_db)
    assert [jwk["kid"] for jwk in jwks["keys"]] == [str(valid.kid)]
    jwk = jwks["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "key_ops" not in jwk
    assert "d" not in jwk  # never publish private key material
    assert str(expired.kid) not in jwks_kids(store, empty_db)


def test_signing_key_is_reused(empty_db: sqlite3.Connection, clock: FakeClock) -> None:
    store = make_store(clock)
    first = store.get_signing_key(empty_db)
    second = store.get_signing_key(empty_db)
    assert first.kid == second.kid
    assert len(stored_keys(empty_db)) == 1


def test_new_key_is_generated_after_expiry(empty_db: sqlite3.Connection, clock: FakeClock) -> None:
    store = make_store(clock)
    first = store.get_signing_key(empty_db)
    clock.advance(LIFETIME + 1)
    second = store.get_signing_key(empty_db)
    assert second.kid != first.kid
    assert second.expires_at > clock()
    assert jwks_kids(store, empty_db) == {str(second.kid)}


def test_cached_keys_skip_decryption(empty_db: sqlite3.Connection, clock: FakeClock) -> None:
    store = make_store(clock)
    store.initialize(empty_db)

    def fail(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("decrypt should not be called for cached keys")

    store._cipher.decrypt = fail  # type: ignore[method-assign]
    assert store.jwks(empty_db)["keys"]


def test_plaintext_keys_from_old_database_get_encrypted(
    empty_db: sqlite3.Connection, clock: FakeClock
) -> None:
    exp = int(clock()) + LIFETIME
    bytes_kid = insert_raw_key(empty_db, rsa_pem(), exp)
    text_kid = insert_raw_key(empty_db, rsa_pem().decode(), exp)

    store = make_store(clock)
    store.initialize(empty_db)

    for row in stored_keys(empty_db):
        assert not bytes(row["key"]).startswith(b"-----BEGIN")
    assert {str(bytes_kid), str(text_kid)} <= jwks_kids(make_store(clock), empty_db)


def test_key_encrypted_with_another_secret_is_skipped(
    empty_db: sqlite3.Connection, clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    other = make_store(clock, secret=secrets.token_hex(32))
    foreign = other.get_signing_key(empty_db)

    store = make_store(clock)
    with caplog.at_level(logging.WARNING):
        own = store.get_signing_key(empty_db)
        store.jwks(empty_db)
    assert own.kid != foreign.kid
    assert jwks_kids(store, empty_db) == {str(own.kid)}
    assert caplog.text.count(f"kid={foreign.kid}") == 1  # warned once, not on every call


def test_editing_exp_in_database_invalidates_key(empty_db: sqlite3.Connection, clock: FakeClock) -> None:
    store = make_store(clock)
    expired = store.get_signing_key(empty_db, expired=True)
    with empty_db:
        empty_db.execute("UPDATE keys SET exp = ? WHERE kid = ?", (int(clock()) + LIFETIME, expired.kid))
    # A fresh store has an empty cache, so it must decrypt and check the exp binding.
    assert str(expired.kid) not in jwks_kids(make_store(clock), empty_db)


def test_non_rsa_key_is_skipped(empty_db: sqlite3.Connection, clock: FakeClock) -> None:
    ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    kid = insert_raw_key(empty_db, ec_pem, int(clock()) + LIFETIME)
    store = make_store(clock)
    store.initialize(empty_db)
    assert str(kid) not in jwks_kids(store, empty_db)


def test_corrupt_row_is_skipped(empty_db: sqlite3.Connection, clock: FakeClock) -> None:
    kid = insert_raw_key(empty_db, b"\x00\x01garbage", int(clock()) + LIFETIME)
    store = make_store(clock)
    assert store.get_signing_key(empty_db).kid != kid
    assert str(kid) not in jwks_kids(store, empty_db)
