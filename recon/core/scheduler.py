from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TypeVar

from recon.core.logger import get_logger

T = TypeVar("T")
log = get_logger("scheduler")


@dataclass
class ScheduledJob:
    name: str
    next_run: datetime
    payload: dict[str, Any]


class JobRunner(ABC):
    """Extensibility hook for cron / cloud scheduler (e.g. Cloud Scheduler → webhook)."""

    @abstractmethod
    async def run(self, job: ScheduledJob) -> None:
        pass


class InProcessScheduler:
    """
    Minimal async scheduler for long-running deployments.
    For production cron, prefer external triggers that invoke the CLI.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task] = {}
        self._stop = asyncio.Event()

    def schedule_interval(
        self,
        name: str,
        interval_seconds: float,
        coro_factory: Callable[[], Awaitable[None]],
    ) -> None:
        async def _loop() -> None:
            while not self._stop.is_set():
                try:
                    await coro_factory()
                except Exception:
                    log.exception("scheduled job %s failed", name)
                try:
                    await asyncio.wait_for(
                        self._stop.wait(), timeout=max(0.1, interval_seconds)
                    )
                    break
                except asyncio.TimeoutError:
                    continue

        self._tasks[name] = asyncio.create_task(_loop(), name=f"sched:{name}")

    async def stop(self) -> None:
        self._stop.set()
        for t in self._tasks.values():
            t.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
