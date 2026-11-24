"""Tests for user storage, credential checks, and auth logging."""

from __future__ import annotations

import sqlite3

import pytest
from argon2 import PasswordHasher

from jwks_server import passwords, users


@pytest.mark.parametrize(
    ("username", "email", "expected"),
    [
        ("bob", "bob@example.com", ("bob", "bob@example.com")),
        ("bob", None, ("bob", None)),
        ("bob", "", ("bob", None)),
    ],
)
def test_validate_registration_accepts_valid_input(username, email, expected) -> None:
    assert users.validate_registration(username, email) == expected


@pytest.mark.parametrize(
    ("username", "email"),
    [
        (None, None),
        ("", None),
        (123, None),
        (" bob", None),
        ("x" * (users.USERNAME_MAX_LENGTH + 1), None),
        ("bob", "not-an-email"),
        ("bob", "bob @example.com"),
        ("bob", 42),
        ("bob", "a" * 250 + "@example.com"),
    ],
)
def test_validate_registration_rejects_bad_input(username, email) -> None:
    with pytest.raises(users.RegistrationError):
        users.validate_registration(username, email)


def test_create_user_stores_only_a_hash(empty_db: sqlite3.Connection) -> None:
    password = users.create_user(empty_db, "bob", "bob@example.com")
    row = empty_db.execute("SELECT * FROM users WHERE username = ?", ("bob",)).fetchone()
    assert row["password_hash"] != password
    assert passwords.verify_password(row["password_hash"], password)
    assert row["date_registered"] is not None
    assert row["last_login"] is None


def test_duplicate_username_is_rejected(empty_db: sqlite3.Connection) -> None:
    users.create_user(empty_db, "bob", "bob@example.com")
    with pytest.raises(users.UserExistsError):
        users.create_user(empty_db, "bob", "other@example.com")


def test_duplicate_email_is_rejected(empty_db: sqlite3.Connection) -> None:
    users.create_user(empty_db, "bob", "bob@example.com")
    with pytest.raises(users.UserExistsError):
        users.create_user(empty_db, "rob", "bob@example.com")


def test_authenticate_returns_user_id(empty_db: sqlite3.Connection) -> None:
    password = users.create_user(empty_db, "bob", None)
    user_id = empty_db.execute("SELECT id FROM users WHERE username = 'bob'").fetchone()["id"]
    assert users.authenticate(empty_db, "bob", password) == user_id


def test_authenticate_rejects_wrong_password(empty_db: sqlite3.Connection) -> None:
    users.create_user(empty_db, "bob", None)
    assert users.authenticate(empty_db, "bob", "wrong") is None


def test_authenticate_rejects_unknown_user(empty_db: sqlite3.Connection) -> None:
    assert users.authenticate(empty_db, "nobody", "whatever") is None


def test_authenticate_upgrades_outdated_hash(empty_db: sqlite3.Connection) -> None:
    old_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("pw")
    with empty_db:
        empty_db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("old", old_hash))
    assert users.authenticate(empty_db, "old", "pw") is not None
    new_hash = empty_db.execute("SELECT password_hash FROM users WHERE username = 'old'").fetchone()[
        "password_hash"
    ]
    assert new_hash != old_hash
    assert not passwords.needs_rehash(new_hash)


def test_record_successful_auth(empty_db: sqlite3.Connection) -> None:
    users.create_user(empty_db, "bob", None)
    user_id = empty_db.execute("SELECT id FROM users WHERE username = 'bob'").fetchone()["id"]
    users.record_successful_auth(empty_db, user_id, "192.0.2.7")

    log = empty_db.execute("SELECT * FROM auth_logs").fetchone()
    assert log["request_ip"] == "192.0.2.7"
    assert log["user_id"] == user_id
    assert log["request_timestamp"] is not None
    last_login = empty_db.execute("SELECT last_login FROM users WHERE id = ?", (user_id,)).fetchone()
    assert last_login["last_login"] is not None


def test_auth_log_requires_existing_user(empty_db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        users.record_successful_auth(empty_db, 999, "192.0.2.7")
