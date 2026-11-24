"""Tests for the sliding-window rate limiter."""

from __future__ import annotations

import pytest

from jwks_server.rate_limiter import SlidingWindowRateLimiter

from .conftest import FakeClock


def test_allows_requests_up_to_the_limit(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(10, 1.0, clock=clock)
    assert all(limiter.check("a").allowed for _ in range(10))


def test_blocks_the_request_over_the_limit(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(10, 1.0, clock=clock)
    for _ in range(10):
        limiter.check("a")
    clock.advance(0.25)
    decision = limiter.check("a")
    assert not decision.allowed
    assert decision.retry_after == pytest.approx(0.75)


def test_window_slides(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(2, 1.0, clock=clock)
    assert limiter.check("a").allowed
    clock.advance(0.5)
    assert limiter.check("a").allowed
    assert not limiter.check("a").allowed
    clock.advance(0.5)  # the first request is now exactly one window old
    assert limiter.check("a").allowed
    assert not limiter.check("a").allowed


def test_rejected_requests_do_not_count(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(1, 1.0, clock=clock)
    assert limiter.check("a").allowed
    for _ in range(5):
        clock.advance(0.1)
        assert not limiter.check("a").allowed
    clock.advance(0.6)
    assert limiter.check("a").allowed


def test_clients_are_limited_separately(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(1, 1.0, clock=clock)
    assert limiter.check("10.0.0.1").allowed
    assert limiter.check("10.0.0.2").allowed
    assert not limiter.check("10.0.0.1").allowed


def test_gradebot_pattern_is_limited(clock: FakeClock) -> None:
    """10 requests 100 ms apart all pass, and the 11th right after is blocked."""
    limiter = SlidingWindowRateLimiter(10, 1.0, clock=clock)
    for _ in range(10):
        clock.advance(0.1)
        assert limiter.check("127.0.0.1").allowed
    clock.advance(0.03)  # time taken by the 10th response
    assert not limiter.check("127.0.0.1").allowed


def test_idle_clients_are_evicted(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(1, 1.0, clock=clock, max_clients=2)
    limiter.check("a")
    limiter.check("b")
    clock.advance(2.0)
    limiter.check("c")
    assert set(limiter._hits) == {"c"}


@pytest.mark.parametrize(("limit", "window"), [(0, 1.0), (10, 0.0), (10, -1.0)])
def test_rejects_invalid_settings(limit: int, window: float) -> None:
    with pytest.raises(ValueError):
        SlidingWindowRateLimiter(limit, window)
