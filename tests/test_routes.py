"""End-to-end tests for the HTTP endpoints."""

from __future__ import annotations

import base64
import sqlite3
import time
import uuid

import jwt
import pytest
from flask.testing import FlaskClient

from jwks_server import create_app
from jwks_server.config import Settings
from jwks_server.db import close_db, get_db, open_db

from .conftest import TEST_SECRET


def verify_with_jwks(client: FlaskClient, token: str) -> dict:
    """Verify a token the way a relying party would, using the JWKS endpoint."""
    kid = jwt.get_unverified_header(token)["kid"]
    jwks = client.get("/.well-known/jwks.json").get_json()
    jwk = next(key for key in jwks["keys"] if key["kid"] == kid)
    return jwt.decode(token, jwt.PyJWK(jwk).key, algorithms=["RS256"])


def auth_log_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]


# JWKS -------------------------------------------------------------------


def test_jwks_returns_public_keys(client: FlaskClient) -> None:
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    keys = response.get_json()["keys"]
    assert len(keys) == 1
    assert {"kid", "kty", "n", "e"} <= keys[0].keys()


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_jwks_rejects_other_methods(client: FlaskClient, method: str) -> None:
    response = client.open("/.well-known/jwks.json", method=method)
    assert response.status_code == 405
    assert response.get_json()["error"]


# /register --------------------------------------------------------------


def test_register_returns_uuid4_password(client: FlaskClient, db_conn: sqlite3.Connection) -> None:
    response = client.post("/register", json={"username": "bob", "email": "bob@example.com"})
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store"
    password = response.get_json()["password"]
    assert uuid.UUID(password).version == 4

    row = db_conn.execute("SELECT * FROM users WHERE username = 'bob'").fetchone()
    assert row["email"] == "bob@example.com"
    assert row["password_hash"].startswith("$argon2id$")
    assert row["password_hash"] != password


def test_register_without_email(client: FlaskClient) -> None:
    assert client.post("/register", json={"username": "bob"}).status_code == 201


def test_register_duplicate_username(client: FlaskClient, registered_user) -> None:
    response = client.post("/register", json={"username": registered_user[0]})
    assert response.status_code == 409


@pytest.mark.parametrize(
    "body",
    [
        {"email": "bob@example.com"},
        {"username": "", "email": "bob@example.com"},
        {"username": "bob", "email": "nope"},
        ["bob"],
    ],
)
def test_register_rejects_bad_body(client: FlaskClient, body) -> None:
    assert client.post("/register", json=body).status_code == 400


def test_register_rejects_non_json(client: FlaskClient) -> None:
    response = client.post("/register", data="username=bob")
    assert response.status_code == 400


def test_register_rejects_oversized_body(client: FlaskClient) -> None:
    response = client.post("/register", data="x" * 20_000, content_type="application/json")
    assert response.status_code == 413


# /auth ------------------------------------------------------------------


def test_auth_with_json_returns_verifiable_token(
    client: FlaskClient, registered_user, db_conn: sqlite3.Connection
) -> None:
    username, password = registered_user
    response = client.post("/auth", json={"username": username, "password": password})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    claims = verify_with_jwks(client, response.get_json()["token"])
    assert claims["sub"] == username


def test_auth_is_logged(client: FlaskClient, registered_user, db_conn: sqlite3.Connection) -> None:
    username, password = registered_user
    client.post("/auth", json={"username": username, "password": password})

    user = db_conn.execute("SELECT id, last_login FROM users WHERE username = ?", (username,)).fetchone()
    log = db_conn.execute("SELECT * FROM auth_logs WHERE user_id = ?", (user["id"],)).fetchone()
    assert log["request_ip"] == "127.0.0.1"
    assert log["request_timestamp"] is not None
    assert user["last_login"] is not None


def test_auth_with_basic_auth(client: FlaskClient, registered_user) -> None:
    username, password = registered_user
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    response = client.post("/auth", headers={"Authorization": f"Basic {encoded}"})
    assert response.status_code == 200


def test_auth_with_form_fields(client: FlaskClient, registered_user) -> None:
    username, password = registered_user
    response = client.post("/auth", data={"username": username, "password": password})
    assert response.status_code == 200


def test_auth_expired_query_returns_expired_token(client: FlaskClient, registered_user) -> None:
    username, password = registered_user
    response = client.post("/auth?expired=true", json={"username": username, "password": password})
    token = response.get_json()["token"]
    assert jwt.decode(token, options={"verify_signature": False})["exp"] < time.time()
    kid = jwt.get_unverified_header(token)["kid"]
    jwks_kids = {key["kid"] for key in client.get("/.well-known/jwks.json").get_json()["keys"]}
    assert kid not in jwks_kids


def test_auth_expired_false_returns_valid_token(client: FlaskClient, registered_user) -> None:
    username, password = registered_user
    response = client.post("/auth?expired=false", json={"username": username, "password": password})
    verify_with_jwks(client, response.get_json()["token"])


def test_auth_wrong_password_is_rejected_and_not_logged(
    client: FlaskClient, registered_user, db_conn: sqlite3.Connection
) -> None:
    response = client.post("/auth", json={"username": registered_user[0], "password": "wrong"})
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert auth_log_count(db_conn) == 0


def test_auth_unknown_user_is_rejected(client: FlaskClient) -> None:
    response = client.post("/auth", json={"username": "ghost", "password": "boo"})
    assert response.status_code == 401


@pytest.mark.parametrize("body", [{}, {"username": "alice"}, {"username": "alice", "password": 5}])
def test_auth_requires_credentials(client: FlaskClient, body) -> None:
    assert client.post("/auth", json=body).status_code == 400


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH", "HEAD"])
def test_auth_rejects_other_methods(client: FlaskClient, method: str) -> None:
    assert client.open("/auth", method=method).status_code == 405


def test_auth_is_rate_limited(tmp_path) -> None:
    # A 60 second window keeps this test independent of how fast the machine is.
    settings = Settings(database_path=str(tmp_path / "rl.db"), rate_limit_window_seconds=60)
    client = create_app(settings, encryption_secret=TEST_SECRET).test_client()
    password = client.post("/register", json={"username": "carol"}).get_json()["password"]
    credentials = {"username": "carol", "password": password}

    for _ in range(10):
        assert client.post("/auth", json=credentials).status_code == 200
    limited = client.post("/auth", json=credentials)
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1

    with open_db(settings.database_path) as conn:
        assert auth_log_count(conn) == 10  # the 429 was not logged


def test_unknown_route_returns_json_404(client: FlaskClient) -> None:
    response = client.get("/nope")
    assert response.status_code == 404
    assert response.get_json()["error"]


def test_close_db_without_open_connection(app) -> None:
    with app.app_context():
        close_db()  # nothing was opened, so this must be a no-op


def test_get_db_reuses_connection_within_a_request(app) -> None:
    with app.app_context():
        assert get_db() is get_db()
