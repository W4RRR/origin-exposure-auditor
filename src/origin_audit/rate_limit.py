"""Asynchronous per-provider rate limiting."""

import asyncio
from time import monotonic


class AsyncRateLimiter:
    """Serialize acquisition to a configured average request rate."""

    def __init__(self, requests_per_second: float) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")
        self.interval = 1.0 / requests_per_second
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def acquire(self) -> None:
        """Wait until one request is allowed."""
        async with self._lock:
            now = monotonic()
            delay = self._next_allowed - now
            if delay > 0:
                await asyncio.sleep(delay)
                now = monotonic()
            self._next_allowed = max(self._next_allowed, now) + self.interval

    async def __aenter__(self) -> "AsyncRateLimiter":
        await self.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        return None
