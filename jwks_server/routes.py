"""HTTP endpoints: JWKS, registration, and authentication."""

from __future__ import annotations

import math

from flask import Blueprint, Response, jsonify, request

from . import users
from .db import get_db
from .services import get_services
from .tokens import issue_token

bp = Blueprint("jwks_server", __name__)

_FALSE_FLAGS = frozenset({"0", "false", "no", "off"})


@bp.get("/.well-known/jwks.json")
def jwks() -> Response:
    """Public keys for every unexpired signing key."""
    return jsonify(get_services().key_store.jwks(get_db()))


@bp.post("/register")
def register() -> tuple[Response, int]:
    """Create a user and return a generated UUIDv4 password (shown only once)."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _json_error("request body must be a JSON object", 400)

    try:
        username, email = users.validate_registration(payload.get("username"), payload.get("email"))
    except users.RegistrationError as exc:
        return _json_error(str(exc), 400)

    try:
        password = users.create_user(get_db(), username, email)
    except users.UserExistsError:
        return _json_error("username or email is already registered", 409)

    return _no_store(jsonify(password=password)), 201


@bp.post("/auth")
def auth() -> tuple[Response, int]:
    """Check credentials and return a signed JWT.

    Order matters here: the rate limit is checked before any Argon2 work, so
    a flood of requests cannot burn CPU. Only successful requests are written
    to auth_logs. Rate-limited and failed attempts are not.
    """
    services = get_services()
    # remote_addr is the TCP peer address. X-Forwarded-For is ignored because
    # any client can set it, which would let it dodge the limiter and fake logs.
    client_ip = request.remote_addr or "unknown"

    decision = services.rate_limiter.check(client_ip)
    if not decision.allowed:
        response, status = _json_error("too many requests", 429)
        response.headers["Retry-After"] = str(max(1, math.ceil(decision.retry_after)))
        return response, status

    credentials = _read_credentials()
    if credentials is None:
        return _json_error("username and password are required", 400)
    username, password = credentials

    conn = get_db()
    user_id = users.authenticate(conn, username, password)
    if user_id is None:
        response, status = _json_error("invalid username or password", 401)
        response.headers["WWW-Authenticate"] = 'Basic realm="jwks-server"'
        return response, status

    signing_key = services.key_store.get_signing_key(conn, expired=_wants_expired_token())
    token = issue_token(signing_key, username, services.token_lifetime_seconds)
    users.record_successful_auth(conn, user_id, client_ip)
    return _no_store(jsonify(token=token)), 200


def _read_credentials() -> tuple[str, str] | None:
    """Read credentials from a JSON body, HTTP Basic auth, or form fields, in that order."""
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        username, password = payload.get("username"), payload.get("password")
    elif request.authorization is not None and request.authorization.type == "basic":
        username = request.authorization.username
        password = request.authorization.password
    else:
        username, password = request.form.get("username"), request.form.get("password")

    if isinstance(username, str) and isinstance(password, str) and username and password:
        return username, password
    return None


def _wants_expired_token() -> bool:
    """True when ?expired is present, unless it is set to an explicit false value."""
    value = request.args.get("expired")
    return value is not None and value.strip().lower() not in _FALSE_FLAGS


def _json_error(message: str, status: int) -> tuple[Response, int]:
    return jsonify(error=message), status


def _no_store(response: Response) -> Response:
    """Responses that carry a password or token must not be cached."""
    response.headers["Cache-Control"] = "no-store"
    return response
