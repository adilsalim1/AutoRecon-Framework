from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Awaitable, Iterator
from typing import TypeVar

T = TypeVar("T")


def chunk_list(items: list[T], size: int) -> Iterator[list[T]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


class RateLimiter:
    """Thread-safe token bucket (approximate) for sync concurrency."""

    def __init__(self, rate_per_second: float) -> None:
        if rate_per_second <= 0:
            self._interval = 0.0
        else:
            self._interval = 1.0 / rate_per_second
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def acquire(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._next_allowed = now + self._interval


class async_rate_limiter:
    """Async context manager enforcing minimum spacing between acquisitions."""

    def __init__(self, rate_per_second: float) -> None:
        if rate_per_second <= 0:
            self._interval = 0.0
        else:
            self._interval = 1.0 / rate_per_second
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next_allowed = now + self._interval

    async def __aexit__(self, *args: object) -> None:
        return None


async def gather_limited(coros: list[Awaitable[T]], limit: int) -> list[T]:
    sem = asyncio.Semaphore(max(1, limit))

    async def _wrap(c: Awaitable[T]) -> T:
        async with sem:
            return await c

    return await asyncio.gather(*(_wrap(c) for c in coros))
