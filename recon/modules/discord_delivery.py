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


# Stay under Discord’s ~25 MB attachment limit (use a safe margin)
_DISCORD_FILE_SAFE_MAX_BYTES = 24 * 1024 * 1024
_DISCORD_MAX_FILES_PER_MESSAGE = 10


async def post_discord_webhook_multipart(
    session: Any,
    url: str,
    payload: dict[str, Any],
    files: list[tuple[str, bytes]],
    *,
    timeout_seconds: float = 35.0,
    retries: int = 3,
    backoff_base: float = 1.25,
) -> bool:
    """
    Execute webhook with attachments (multipart/form-data).
    `files` items are (filename, raw_bytes). Discord allows up to 10 files per request.
    """
    if aiohttp is None:
        return False
    if not _valid_discord_webhook(url):
        _log.warning("invalid or missing Discord webhook URL; skip multipart POST")
        return False
    if not files or len(files) > _DISCORD_MAX_FILES_PER_MESSAGE:
        _log.warning(
            "multipart webhook: need 1..%s files, got %s",
            _DISCORD_MAX_FILES_PER_MESSAGE,
            len(files),
        )
        return False
    to = aiohttp.ClientTimeout(total=timeout_seconds)
    delay = backoff_base
    for attempt in range(max(1, retries)):
        try:
            form = aiohttp.FormData()
            form.add_field(
                "payload_json",
                json.dumps(payload, default=str),
                content_type="application/json",
            )
            for idx, (filename, raw) in enumerate(files):
                form.add_field(
                    f"files[{idx}]",
                    raw,
                    filename=filename or f"attachment_{idx}.bin",
                    content_type="text/plain",
                )
            async with session.post(url, data=form, timeout=to) as resp:
                if resp.status in (200, 201, 202, 204):
                    return True
                text = await resp.text()
                _log.warning(
                    "discord multipart HTTP %s (attempt %s/%s): %s",
                    resp.status,
                    attempt + 1,
                    retries,
                    text[:300],
                )
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _log.warning(
                "discord multipart error (attempt %s/%s): %s",
                attempt + 1,
                retries,
                e,
            )
        if attempt < retries - 1:
            await asyncio.sleep(delay)
            delay *= 1.8
    return False


async def post_multipart_many(
    jobs: list[tuple[str, dict[str, Any], list[tuple[str, bytes]]]],
    *,
    timeout_seconds: float = 35.0,
    retries: int = 3,
) -> None:
    """Each job is (webhook_url, payload_json_dict, files). One POST per job (≤10 files)."""
    if aiohttp is None:
        _log.error("aiohttp not installed; pip install aiohttp for Discord delivery")
        return
    async with aiohttp.ClientSession() as session:
        tasks = [
            post_discord_webhook_multipart(
                session,
                url,
                payload,
                files,
                timeout_seconds=timeout_seconds,
                retries=retries,
            )
            for url, payload, files in jobs
            if url and files
        ]
        if tasks:
            await asyncio.gather(*tasks)


def run_discord_multipart_posts_sync(
    jobs: list[tuple[str, dict[str, Any], list[tuple[str, bytes]]]],
    *,
    timeout_seconds: float = 35.0,
    retries: int = 3,
) -> None:
    """Sync entry: one or more multipart webhook posts (each ≤10 files)."""
    if not jobs:
        return
    if aiohttp is None:
        _log.error("aiohttp not installed; pip install aiohttp")
        return
    try:
        asyncio.run(
            post_multipart_many(
                jobs, timeout_seconds=timeout_seconds, retries=retries
            )
        )
    except RuntimeError:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(
                lambda: asyncio.run(
                    post_multipart_many(
                        jobs,
                        timeout_seconds=timeout_seconds,
                        retries=retries,
                    )
                )
            ).result(timeout=timeout_seconds * len(jobs) + 120)


def split_oversized_text_files(
    files: list[tuple[str, bytes]], max_bytes: int = _DISCORD_FILE_SAFE_MAX_BYTES
) -> list[tuple[str, bytes]]:
    """
    Split any single attachment that exceeds max_bytes into numbered parts
    (line-oriented split for .txt / .jsonl).
    """
    out: list[tuple[str, bytes]] = []
    for name, data in files:
        if len(data) <= max_bytes:
            out.append((name, data))
            continue
        if b"\n" not in data:
            # binary-ish: hard slice
            base = name.rsplit(".", 1)[0] if "." in name else name
            ext = f".{name.rsplit('.', 1)[-1]}" if "." in name else ".bin"
            part = 1
            offset = 0
            while offset < len(data):
                chunk = data[offset : offset + max_bytes]
                out.append((f"{base}_part{part:03d}{ext}", chunk))
                part += 1
                offset += len(chunk)
            continue
        lines = data.split(b"\n")
        buf: list[bytes] = []
        size = 0
        part = 1
        base = name.rsplit(".", 1)[0] if "." in name else name
        ext = f".{name.rsplit('.', 1)[-1]}" if "." in name else ".txt"

        def flush() -> None:
            nonlocal buf, size, part
            if not buf:
                return
            out.append((f"{base}_part{part:03d}{ext}", b"\n".join(buf)))
            part += 1
            buf = []
            size = 0

        for line in lines:
            ln = line + b"\n"
            if len(ln) > max_bytes:
                flush()
                i = 0
                while i < len(line):
                    out.append(
                        (
                            f"{base}_part{part:03d}{ext}",
                            line[i : i + max_bytes],
                        )
                    )
                    part += 1
                    i += max_bytes
                continue
            if size + len(ln) > max_bytes and buf:
                flush()
            buf.append(line)
            size += len(ln)
        flush()
    return out


def batch_files_for_discord(
    files: list[tuple[str, bytes]],
) -> list[list[tuple[str, bytes]]]:
    """Chunk into batches of at most 10 files and ≤ safe size per batch (rough check)."""
    split = split_oversized_text_files(files)
    batches: list[list[tuple[str, bytes]]] = []
    cur: list[tuple[str, bytes]] = []
    cur_size = 0
    for name, raw in split:
        if len(cur) >= _DISCORD_MAX_FILES_PER_MESSAGE or (
            cur and cur_size + len(raw) > _DISCORD_FILE_SAFE_MAX_BYTES
        ):
            batches.append(cur)
            cur = []
            cur_size = 0
        cur.append((name, raw))
        cur_size += len(raw)
    if cur:
        batches.append(cur)
    return batches


def multipart_jobs_for_webhook(
    webhook_url: str,
    base_payload: dict[str, Any],
    files: list[tuple[str, bytes]],
) -> list[tuple[str, dict[str, Any], list[tuple[str, bytes]]]]:
    """
    Build a list of (url, payload, files_batch) for sequential posting (all parts).
    First batch keeps embeds from base_payload; later batches get short content only.
    """
    batches = batch_files_for_discord(files)
    if not batches:
        return []
    jobs: list[tuple[str, dict[str, Any], list[tuple[str, bytes]]]] = []
    total = len(batches)
    for i, batch in enumerate(batches):
        pl: dict[str, Any] = dict(base_payload)
        if i > 0:
            pl.pop("embeds", None)
            prev = (base_payload.get("content") or "").strip()
            pl["content"] = (
                (prev + f" _(files {i + 1}/{total})_") if prev else f"_Attachments {i + 1}/{total}_"
            )[:2000]
        jobs.append((webhook_url, pl, batch))
    return jobs
