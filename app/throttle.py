"""In process rate limiting for authentication.

The platform holds evidence from real intrusions, so its own login endpoint is
worth attacking. This is a sliding window counter keyed on the account and on
the calling address. It is deliberately simple and has one important limit: the
state lives in the process, so a deployment running several workers needs a
shared store instead. That is called out in the README rather than pretended
away.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, bucket: deque[float], now: float) -> None:
        cutoff = now - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

    def check(self, key: str) -> tuple[bool, int]:
        """Return whether the key is allowed and how long to wait if it is not."""
        now = time.monotonic()
        with self._lock:
            bucket = self._events.get(key)
            if bucket is None:
                return True, 0
            self._prune(bucket, now)
            if len(bucket) < self.limit:
                return True, 0
            retry_after = int(self.window - (now - bucket[0])) + 1
            return False, max(retry_after, 1)

    def record(self, key: str) -> None:
        """Record one failed attempt."""
        now = time.monotonic()
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            self._prune(bucket, now)
            bucket.append(now)
            if len(self._events) > 20000:
                self._evict(now)

    def reset(self, key: str) -> None:
        """Clear the counter, called after a successful authentication."""
        with self._lock:
            self._events.pop(key, None)

    def _evict(self, now: float) -> None:
        stale = [key for key, bucket in self._events.items()
                 if not bucket or bucket[-1] < now - self.window]
        for key in stale:
            self._events.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


# Failures per account and per source address inside a five minute window.
account_limiter = SlidingWindowLimiter(limit=10, window_seconds=300)
address_limiter = SlidingWindowLimiter(limit=40, window_seconds=300)


def client_address(request) -> str:
    """Best effort caller address, preferring the proxy header when present."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    client = getattr(request, "client", None)
    return (client.host if client else "unknown")[:64]
