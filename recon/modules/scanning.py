from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from recon.core.logger import get_logger
from recon.models.assets import Asset
from recon.models.findings import Finding
from recon.plugins.base import RawScanResult, ScanContext, ScannerPlugin
from recon.utils.helpers import RateLimiter, async_rate_limiter, gather_limited

log = get_logger("scanning")


class ScanEngine:
    """
    Central scanning orchestration: plugins, parallelism, rate limits,
    normalized findings, duplicate suppression.
    """

    def __init__(
        self,
        plugins: list[ScannerPlugin],
        parallel_workers: int,
        rate_limit_per_second: float,
        skip_duplicates: bool,
        has_fingerprint: Callable[[str], bool],
        record_fingerprint: Callable[[str, dict[str, Any]], None],
        extra_context: dict[str, Any] | None = None,
    ) -> None:
        self._plugins = plugins
        self._parallel_workers = max(1, parallel_workers)
        self._rate = rate_limit_per_second
        self._skip_duplicates = skip_duplicates
        self._has_fp = has_fingerprint
        self._record_fp = record_fingerprint
        self._extra_context = dict(extra_context or {})

    def _context(self, domain: str) -> ScanContext:
        return ScanContext(
            domain=domain,
            rate_limit_per_second=self._rate,
            metadata=dict(self._extra_context),
        )

    def _execute_scan(
        self,
        plugin: ScannerPlugin,
        asset: Asset,
        domain: str,
    ) -> tuple[list[Finding], RawScanResult | None, str | None]:
        fp = asset.fingerprint_for_scan(plugin.name)
        if self._skip_duplicates and self._has_fp(fp):
            log.debug("skip duplicate scan %s %s", plugin.name, asset.identifier)
            return [], None, fp
        raw = plugin.run([asset], self._context(domain))
        if not raw.success:
            log.warning(
                "scanner %s failed for %s: %s",
                plugin.name,
                asset.identifier,
                raw.error_message,
            )
            return [], raw, fp
        parsed = plugin.parse(raw)
        normalized = plugin.normalize(parsed)
        for f in normalized:
            if not f.asset_id:
                f.asset_id = asset.stable_id()
        self._record_fp(
            fp,
            {
                "scanner": plugin.name,
                "asset": asset.identifier,
                "run": str(uuid.uuid4()),
            },
        )
        return normalized, raw, fp

    def execute_sequential(
        self,
        domain: str,
        assets: list[Asset],
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        findings: list[Finding] = []
        records: list[dict[str, Any]] = []
        limiter = RateLimiter(self._rate)
        for plugin in self._plugins:
            for asset in assets:
                limiter.acquire()
                fnds, raw, fp = self._execute_scan(plugin, asset, domain)
                findings.extend(fnds)
                if raw is not None:
                    records.append(self._scan_record(plugin.name, asset, raw, fp))
        return findings, records

    def execute_parallel(
        self,
        domain: str,
        assets: list[Asset],
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        findings: list[Finding] = []
        records: list[dict[str, Any]] = []
        limiter = RateLimiter(self._rate)
        tasks: list[tuple[ScannerPlugin, Asset]] = [
            (p, a) for p in self._plugins for a in assets
        ]

        def _work(p: ScannerPlugin, a: Asset) -> tuple[list[Finding], RawScanResult | None, str | None]:
            limiter.acquire()
            return self._execute_scan(p, a, domain)

        with ThreadPoolExecutor(max_workers=self._parallel_workers) as pool:
            futures = {pool.submit(_work, p, a): (p, a) for p, a in tasks}
            for fut in as_completed(futures):
                p, a = futures[fut]
                try:
                    fnds, raw, fp = fut.result()
                except Exception:
                    log.exception("parallel scan failed %s %s", p.name, a.identifier)
                    continue
                findings.extend(fnds)
                if raw is not None:
                    records.append(self._scan_record(p.name, a, raw, fp))
        return findings, records

    async def execute_async(
        self,
        domain: str,
        assets: list[Asset],
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        rl = async_rate_limiter(self._rate)
        findings: list[Finding] = []
        records: list[dict[str, Any]] = []
        lock = asyncio.Lock()

        async def _one(plugin: ScannerPlugin, asset: Asset) -> None:
            nonlocal findings, records
            fp = asset.fingerprint_for_scan(plugin.name)
            if self._skip_duplicates and self._has_fp(fp):
                return
            async with rl:
                raw = await plugin.run_async([asset], self._context(domain))
            if not raw.success:
                log.warning(
                    "scanner %s failed for %s: %s",
                    plugin.name,
                    asset.identifier,
                    raw.error_message,
                )
                return
            parsed = plugin.parse(raw)
            normalized = plugin.normalize(parsed)
            for f in normalized:
                if not f.asset_id:
                    f.asset_id = asset.stable_id()
            self._record_fp(
                fp,
                {
                    "scanner": plugin.name,
                    "asset": asset.identifier,
                    "run": str(uuid.uuid4()),
                },
            )
            async with lock:
                findings.extend(normalized)
                records.append(self._scan_record(plugin.name, asset, raw, fp))

        coros = [_one(p, a) for p in self._plugins for a in assets]
        await gather_limited(coros, self._parallel_workers)
        return findings, records

    @staticmethod
    def _scan_record(
        plugin_name: str,
        asset: Asset,
        raw: RawScanResult,
        fingerprint: str | None,
    ) -> dict[str, Any]:
        return {
            "plugin": plugin_name,
            "asset": asset.identifier,
            "fingerprint": fingerprint,
            "success": raw.success,
            "captured_at": raw.captured_at.isoformat(),
            "targets": raw.targets,
        }
