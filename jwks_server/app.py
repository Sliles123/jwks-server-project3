"""Application factory."""

from __future__ import annotations

from flask import Flask, Response, json
from werkzeug.exceptions import HTTPException

from .config import Settings, load_encryption_secret
from .crypto import KeyCipher
from .db import close_db, init_db, open_db
from .keystore import KeyStore
from .rate_limiter import SlidingWindowRateLimiter
from .routes import bp
from .services import EXTENSION_KEY, Services


def create_app(
    settings: Settings | None = None,
    encryption_secret: str | None = None,
    *,
    provision_keys: bool = True,
) -> Flask:
    """Build and configure the Flask app.

    Args:
        settings: Non-secret settings. Defaults to Settings().
        encryption_secret: AES key material. Read from NOT_MY_KEY when omitted.
        provision_keys: Prepare signing keys right away. main.py passes False
            so it can bind the port first and prepare keys right after.
    """
    settings = settings or Settings()
    secret = load_encryption_secret() if encryption_secret is None else encryption_secret
    cipher = KeyCipher.from_secret(secret)

    app = Flask(__name__)
    app.config.update(
        DATABASE=settings.database_path,
        MAX_CONTENT_LENGTH=settings.max_request_bytes,
    )

    init_db(settings.database_path)
    app.extensions[EXTENSION_KEY] = Services(
        key_store=KeyStore(cipher, settings.key_lifetime_seconds),
        rate_limiter=SlidingWindowRateLimiter(
            settings.rate_limit_requests, settings.rate_limit_window_seconds
        ),
        token_lifetime_seconds=settings.token_lifetime_seconds,
    )
    if provision_keys:
        prepare_keys(app)

    app.teardown_appcontext(close_db)
    app.register_error_handler(HTTPException, _http_error_as_json)
    app.register_blueprint(bp)
    return app


def prepare_keys(app: Flask) -> None:
    """Encrypt any plaintext keys and make sure a valid and an expired key exist."""
    services: Services = app.extensions[EXTENSION_KEY]
    with open_db(app.config["DATABASE"]) as conn:
        services.key_store.initialize(conn)


def _http_error_as_json(error: HTTPException) -> Response:
    """Return framework errors (404, 405, 413...) as JSON, keeping headers like Allow."""
    response = error.get_response()
    response.set_data(json.dumps({"error": error.description}))
    response.content_type = "application/json"
    return response
