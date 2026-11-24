"""App-wide objects shared by every request."""

from __future__ import annotations

from dataclasses import dataclass

from flask import current_app

from .keystore import KeyStore
from .rate_limiter import SlidingWindowRateLimiter

EXTENSION_KEY = "jwks_server"


@dataclass
class Services:
    """Long-lived objects stored on the Flask app."""

    key_store: KeyStore
    rate_limiter: SlidingWindowRateLimiter
    token_lifetime_seconds: int


def get_services() -> Services:
    """Return the Services for the app handling the current request."""
    return current_app.extensions[EXTENSION_KEY]
