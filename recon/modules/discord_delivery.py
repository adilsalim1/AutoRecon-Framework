"""
Async Discord webhook delivery with retries and timeouts (aiohttp).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

_log = logging.getLogger("recon.discord_delivery")

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]


def _valid_discord_webhook(url: str) -> bool:
    u = (url or "").strip().lower()
    return u.startswith("https://discord.com/api/webhooks/") or u.startswith(
        "https://discordapp.com/api/webhooks/"
    )


async def post_discord_webhook(
    session: Any,
    url: str,
    payload: dict[str, Any],
    *,
    timeout_seconds: float = 35.0,
    retries: int = 3,
    backoff_base: float = 1.25,
) -> bool:
    if not _valid_discord_webhook(url):
        _log.warning("invalid or missing Discord webhook URL; skip POST")
        return False
    body = json.dumps(payload, default=str).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    to = aiohttp.ClientTimeout(total=timeout_seconds)
    delay = backoff_base
    for attempt in range(max(1, retries)):
        try:
            async with session.post(url, data=body, headers=headers, timeout=to) as resp:
                if resp.status in (200, 201, 202, 204):
                    return True
                text = await resp.text()
                _log.warning(
                    "discord webhook HTTP %s (attempt %s/%s): %s",
                    resp.status,
                    attempt + 1,
                    retries,
                    text[:300],
                )
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _log.warning(
                "discord webhook error (attempt %s/%s): %s",
                attempt + 1,
                retries,
                e,
            )
        if attempt < retries - 1:
            await asyncio.sleep(delay)
            delay *= 1.8
    return False


async def post_many(
    payloads: list[tuple[str, dict[str, Any]]],
    *,
    timeout_seconds: float = 35.0,
    retries: int = 3,
) -> None:
    if aiohttp is None:
        _log.error("aiohttp not installed; pip install aiohttp for Discord delivery")
        return
    async with aiohttp.ClientSession() as session:
        tasks = [
            post_discord_webhook(
                session,
                url,
                payload,
                timeout_seconds=timeout_seconds,
                retries=retries,
            )
            for url, payload in payloads
            if url and payload
        ]
        if tasks:
            await asyncio.gather(*tasks)


def run_discord_posts_sync(
    payloads: list[tuple[str, dict[str, Any]]],
    *,
    timeout_seconds: float = 35.0,
    retries: int = 3,
) -> None:
    """Run async delivery from sync code (CLI / pipeline)."""
    if not payloads:
        return
    if aiohttp is None:
        _log.error("aiohttp not installed; pip install aiohttp")
        return
    try:
        asyncio.run(
            post_many(payloads, timeout_seconds=timeout_seconds, retries=retries)
        )
    except RuntimeError:
        # Nested loop (e.g. some test env): new loop in thread
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(
                lambda: asyncio.run(
                    post_many(
                        payloads,
                        timeout_seconds=timeout_seconds,
                        retries=retries,
                    )
                )
            ).result(timeout=timeout_seconds * len(payloads) + 60)
