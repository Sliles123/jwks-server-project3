"""Tests for configuration loading."""

from __future__ import annotations

import logging

import pytest

from jwks_server import create_app
from jwks_server.config import ENCRYPTION_KEY_ENV, ConfigError, Settings, load_encryption_secret

from .conftest import TEST_SECRET


def test_missing_secret_raises() -> None:
    with pytest.raises(ConfigError, match=ENCRYPTION_KEY_ENV):
        load_encryption_secret({})


def test_blank_secret_raises() -> None:
    with pytest.raises(ConfigError):
        load_encryption_secret({ENCRYPTION_KEY_ENV: "   "})


def test_returns_secret() -> None:
    assert load_encryption_secret({ENCRYPTION_KEY_ENV: TEST_SECRET}) == TEST_SECRET


def test_short_secret_logs_warning_without_the_value(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        assert load_encryption_secret({ENCRYPTION_KEY_ENV: "short-value"}) == "short-value"
    assert "shorter than" in caplog.text
    assert "short-value" not in caplog.text


def test_reads_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENCRYPTION_KEY_ENV, TEST_SECRET)
    assert load_encryption_secret() == TEST_SECRET


def test_create_app_refuses_to_start_without_secret(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    monkeypatch.delenv(ENCRYPTION_KEY_ENV, raising=False)
    with pytest.raises(ConfigError):
        create_app(settings)


def test_create_app_reads_secret_from_environment(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    monkeypatch.setenv(ENCRYPTION_KEY_ENV, TEST_SECRET)
    app = create_app(settings)
    assert app.test_client().get("/.well-known/jwks.json").status_code == 200
