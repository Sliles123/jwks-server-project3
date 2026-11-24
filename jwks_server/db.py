"""SQLite schema and connection helpers."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from flask import current_app, g

KEYS_TABLE = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
"""

AUTH_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
"""

SCHEMA = (KEYS_TABLE, USERS_TABLE, AUTH_LOGS_TABLE)


def connect(path: str) -> sqlite3.Connection:
    """Open a connection with name-based row access and foreign keys enforced."""
    conn = sqlite3.connect(path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def open_db(path: str) -> Iterator[sqlite3.Connection]:
    """Yield a connection that is always closed afterwards."""
    conn = connect(path)
    try:
        yield conn
    finally:
        conn.close()


def init_db(path: str) -> None:
    """Create every table that does not exist yet."""
    with open_db(path) as conn, conn:
        for statement in SCHEMA:
            conn.execute(statement)


def get_db() -> sqlite3.Connection:
    """Return the current request's connection, opening it on first use."""
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    """Close the request's connection. Registered as an app teardown hook."""
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()
