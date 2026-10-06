"""In-memory sliding-window rate limiter for the service boundary (swap for Redis when scaling out)."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


class RateLimiter:
    def __init__(self, limit: int = 30, window_s: float = 60.0, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window_s, clock
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = self.clock()
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()


ai_limiter = RateLimiter()


def limit_ai(request: Request) -> None:
    key = request.client.host if request.client else "unknown"
    if not ai_limiter.allow(key):
        raise HTTPException(429, "Rate limit exceeded; try again shortly")
