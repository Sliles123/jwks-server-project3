"""Runtime configuration for the JWKS server.

The AES key material is only ever read from the NOT_MY_KEY environment
variable. Nothing in this package stores, logs, or prints its value.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass

logger = logging.getLogger(__name__)

ENCRYPTION_KEY_ENV = "NOT_MY_KEY"
DEFAULT_DATABASE_PATH = "totally_not_my_privateKeys.db"
RECOMMENDED_SECRET_LENGTH = 32


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class Settings:
    """Non-secret settings. The defaults match what the gradebot expects."""

    database_path: str = DEFAULT_DATABASE_PATH
    host: str = "127.0.0.1"
    port: int = 8080
    key_lifetime_seconds: int = 3600
    token_lifetime_seconds: int = 900
    rate_limit_requests: int = 10
    rate_limit_window_seconds: float = 1.0
    max_request_bytes: int = 16 * 1024


def load_encryption_secret(environ: Mapping[str, str] | None = None) -> str:
    """Return the value of NOT_MY_KEY, or raise ConfigError if it is missing."""
    env = os.environ if environ is None else environ
    secret = env.get(ENCRYPTION_KEY_ENV, "")
    if not secret.strip():
        raise ConfigError(
            f"{ENCRYPTION_KEY_ENV} is not set. Set it to a long random value before starting the server."
        )
    if len(secret) < RECOMMENDED_SECRET_LENGTH:
        logger.warning(
            "%s is shorter than %d characters. A longer random value is recommended.",
            ENCRYPTION_KEY_ENV,
            RECOMMENDED_SECRET_LENGTH,
        )
    return secret
