"""User registration, credential checks, and authentication logging."""

from __future__ import annotations

import sqlite3
from functools import lru_cache

from . import passwords

USERNAME_MAX_LENGTH = 64
EMAIL_MAX_LENGTH = 254


class RegistrationError(ValueError):
    """Raised when registration input is invalid."""


class UserExistsError(Exception):
    """Raised when the username or email is already registered."""


def validate_registration(username: object, email: object) -> tuple[str, str | None]:
    """Check registration input and return (username, email or None)."""
    if not isinstance(username, str) or not username or username != username.strip():
        raise RegistrationError("username must be a non-empty string without leading or trailing spaces")
    if len(username) > USERNAME_MAX_LENGTH:
        raise RegistrationError(f"username must be at most {USERNAME_MAX_LENGTH} characters")

    if email is None or email == "":
        return username, None
    if (
        not isinstance(email, str)
        or len(email) > EMAIL_MAX_LENGTH
        or "@" not in email
        or any(ch.isspace() for ch in email)
    ):
        raise RegistrationError("email must be a valid email address")
    return username, email


def create_user(conn: sqlite3.Connection, username: str, email: str | None) -> str:
    """Create a user with a generated password and return that password.

    Only the Argon2 hash is stored. The plaintext password is returned once
    so the caller can hand it to the user.
    """
    password = passwords.generate_password()
    password_hash = passwords.hash_password(password)
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                (username, password_hash, email),
            )
    except sqlite3.IntegrityError as exc:
        raise UserExistsError("username or email is already registered") from exc
    return password


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> int | None:
    """Return the user's id if the credentials are valid, otherwise None."""
    row = conn.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        # Do the same Argon2 work as a real check so response timing does
        # not reveal which usernames exist.
        passwords.verify_password(_dummy_hash(), password)
        return None
    if not passwords.verify_password(row["password_hash"], password):
        return None
    if passwords.needs_rehash(row["password_hash"]):
        with conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (passwords.hash_password(password), row["id"]),
            )
    return int(row["id"])


def record_successful_auth(conn: sqlite3.Connection, user_id: int, request_ip: str) -> None:
    """Write an auth_logs row and update the user's last_login in one transaction."""
    with conn:
        conn.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (request_ip, user_id),
        )
        conn.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user_id,),
        )


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """A throwaway hash used to equalize timing for unknown usernames."""
    return passwords.hash_password(passwords.generate_password())
