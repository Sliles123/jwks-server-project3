"""Tests for the main.py entry point."""

from __future__ import annotations

import pytest

import main
from jwks_server.config import DEFAULT_DATABASE_PATH, ENCRYPTION_KEY_ENV
from jwks_server.db import open_db

from .conftest import TEST_SECRET


class FakeServer:
    """Stands in for the Werkzeug server so no real port is opened."""

    def __init__(self, events: list[str]) -> None:
        self.events = events

    def serve_forever(self) -> None:
        with open_db(DEFAULT_DATABASE_PATH) as conn:
            key_count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        self.events.append(f"serve (keys={key_count})")
        raise KeyboardInterrupt

    def server_close(self) -> None:
        self.events.append("close")


def test_main_exits_with_error_without_secret(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(ENCRYPTION_KEY_ENV, raising=False)
    assert main.main() == 1


def test_main_binds_then_prepares_keys_then_serves(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ENCRYPTION_KEY_ENV, TEST_SECRET)
    events: list[str] = []

    def fake_make_server(host: str, port: int, app: object, threaded: bool) -> FakeServer:
        events.append(f"bind {host}:{port} threaded={threaded}")
        return FakeServer(events)

    monkeypatch.setattr(main, "make_server", fake_make_server)
    assert main.main() == 0
    assert events == ["bind 127.0.0.1:8080 threaded=True", "serve (keys=2)", "close"]
    assert (tmp_path / DEFAULT_DATABASE_PATH).exists()
