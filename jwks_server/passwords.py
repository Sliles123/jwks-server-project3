"""Password generation and Argon2id hashing."""

from __future__ import annotations

import uuid

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Argon2id settings from the OWASP Password Storage Cheat Sheet (minimum
# recommended config): 19 MiB of memory, 2 iterations, 1 lane. A verify takes
# roughly 25 ms, which keeps /auth well inside the 100 ms per request that a
# 10 requests/second rate limit leaves. argon2-cffi's heavier default
# (64 MiB, t=3, p=4) took ~150 ms per verify in testing.
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST_KIB = 19 * 1024
ARGON2_PARALLELISM = 1
ARGON2_HASH_LENGTH = 32  # bytes
ARGON2_SALT_LENGTH = 16  # bytes, a new random salt for every hash

_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST_KIB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LENGTH,
    salt_len=ARGON2_SALT_LENGTH,
)


def generate_password() -> str:
    """Return a new UUIDv4 password (122 random bits from os.urandom)."""
    return str(uuid.uuid4())


def hash_password(password: str) -> str:
    """Hash a password with Argon2id. Salt and settings are encoded in the result."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True only if the password matches the stored hash."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Return True if the hash was made with settings other than the current ones."""
    return _hasher.check_needs_rehash(password_hash)
