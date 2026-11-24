"""Sliding-window rate limiter for POST /auth."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitDecision:
    """Result of a rate limit check. retry_after is in seconds."""

    allowed: bool
    retry_after: float = 0.0


class SlidingWindowRateLimiter:
    """Allow at most `limit` requests per `window_seconds` for each client.

    A log of accepted request times is kept per client. Unlike a fixed
    window, a client cannot get twice the limit through by sending a burst
    on each side of a window boundary. Rejected requests are not recorded,
    so a client that keeps retrying still gets `limit` requests per window.
    """

    def __init__(
        self,
        limit: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        max_clients: int = 10_000,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._max_clients = max_clients
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, client_id: str) -> RateLimitDecision:
        """Record a request from client_id if it is under the limit."""
        now = self._clock()
        cutoff = now - self._window
        with self._lock:
            hits = self._hits.get(client_id)
            if hits is None:
                if len(self._hits) >= self._max_clients:
                    self._evict_idle(cutoff)
                hits = self._hits[client_id] = deque()

            while hits and hits[0] <= cutoff:
                hits.popleft()

            if len(hits) >= self._limit:
                # The oldest request leaves the window at hits[0] + window.
                return RateLimitDecision(allowed=False, retry_after=hits[0] - cutoff)

            hits.append(now)
            return RateLimitDecision(allowed=True)

    def _evict_idle(self, cutoff: float) -> None:
        """Forget clients with no requests in the current window to bound memory."""
        idle = [client for client, hits in self._hits.items() if not hits or hits[-1] <= cutoff]
        for client in idle:
            del self._hits[client]
