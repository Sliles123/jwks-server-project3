"""Shared pytest fixtures."""

from __future__ import annotations

import secrets
import sqlite3
from collections.abc import Iterator

import pytest
from flask import Flask
from flask.testing import FlaskClient

from jwks_server import create_app
from jwks_server.config import Settings
from jwks_server.db import init_db, open_db

# A random value per test run, so no secret is ever written into the repo.
TEST_SECRET = secrets.token_hex(32)


class FakeClock:
    """A controllable clock for time-based tests."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(database_path=str(tmp_path / "test.db"))


@pytest.fixture
def app(settings: Settings) -> Flask:
    return create_app(settings, encryption_secret=TEST_SECRET)


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


@pytest.fixture
def db_conn(app: Flask, settings: Settings) -> Iterator[sqlite3.Connection]:
    """A connection to the app's database (tables and keys already created)."""
    with open_db(settings.database_path) as conn:
        yield conn


@pytest.fixture
def empty_db(tmp_path) -> Iterator[sqlite3.Connection]:
    """A connection to a database with the schema but no rows."""
    path = str(tmp_path / "empty.db")
    init_db(path)
    with open_db(path) as conn:
        yield conn


@pytest.fixture
def registered_user(client: FlaskClient) -> tuple[str, str]:
    """Register a user through the API and return (username, password)."""
    response = client.post("/register", json={"username": "alice", "email": "alice@example.com"})
    assert response.status_code == 201
    return "alice", response.get_json()["password"]
