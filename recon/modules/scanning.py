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

    def _assets_for_plugin(self, plugin: ScannerPlugin, assets: list[Asset]) -> list[Asset]:
        """vhost_ffuf_scanner uses only apex/root targets from context (see PipelineEngine)."""
        if plugin.name != "vhost_ffuf_scanner":
            return assets
        sub = self._extra_context.get("vhost_scan_assets")
        if isinstance(sub, list) and sub:
            return list(sub)
        return assets

    def _context(self, domain: str) -> ScanContext:
        meta = {
            k: v
            for k, v in self._extra_context.items()
            if k != "vhost_scan_assets"
        }
        return ScanContext(
            domain=domain,
            rate_limit_per_second=self._rate,
            metadata=meta,
        )

    def _host_under_waf(self, asset: Asset) -> bool:
        pr = self._extra_context.get("pipeline_runtime")
        if not isinstance(pr, dict):
            return False
        wmap = pr.get("waf_by_host")
        if not isinstance(wmap, dict):
            return False
        key = asset.identifier.lower().strip().rstrip(".")
        return key in wmap

    def _execute_scan(
        self,
        plugin: ScannerPlugin,
        asset: Asset,
        domain: str,
    ) -> tuple[list[Finding], RawScanResult | None, str | None]:
        fp = asset.fingerprint_for_scan(plugin.name)
        if self._skip_duplicates and self._has_fp(fp):
            log.info(
                "scan skip (already scanned) %s → %s",
                plugin.name,
                asset.identifier,
            )
            return [], None, fp
        if self._extra_context.get("waf_skip_aggressive", True):
            tier = getattr(plugin, "scan_tier", "safe")
            if tier == "aggressive" and self._host_under_waf(asset):
                wmap = self._extra_context.get("pipeline_runtime") or {}
                wv = ""
                if isinstance(wmap, dict):
                    inner = wmap.get("waf_by_host")
                    if isinstance(inner, dict):
                        wv = str(
                            inner.get(
                                asset.identifier.lower().strip().rstrip("."),
                                "",
                            )
                        )
                log.info(
                    "scan skip aggressive %s → %s (WAF: %s)",
                    plugin.name,
                    asset.identifier,
                    wv or "unknown",
                )
                return [], None, None
        log.info(
            "scan start %s → %s",
            plugin.name,
            asset.identifier,
        )
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
        log.info(
            "scan done %s → %s (%s findings)",
            plugin.name,
            asset.identifier,
            len(normalized),
        )
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
            for asset in self._assets_for_plugin(plugin, assets):
                limiter.acquire()
                fnds, raw, fp = self._execute_scan(plugin, asset, domain)
                findings.extend(fnds)
                if raw is not None:
                    records.append(self._scan_record(plugin.name, asset, raw, fp))
        return findings, records

    def httpx_probe_partition(
        self,
        domain: str,
        assets: list[Asset],
        httpx_plugin: ScannerPlugin,
        *,
        parallel: bool,
    ) -> tuple[list[Finding], list[dict[str, Any]], list[Asset]]:
        """
        Run httpx_scanner on every asset; return findings/records plus assets considered *live*
        (≥1 JSON line from httpx, or httpx skipped as duplicate fingerprint).
        """
        findings: list[Finding] = []
        records: list[dict[str, Any]] = []
        live: list[Asset] = []

        def _consider_live(raw: RawScanResult | None) -> bool:
            if raw is None:
                return True
            if not raw.success:
                return False
            lines = raw.raw_payload.get("lines") if raw.raw_payload else None
            return bool(lines)

        if parallel and self._parallel_workers > 1:
            limiter = RateLimiter(self._rate)

            def _work(asset: Asset) -> tuple[list[Finding], RawScanResult | None, str | None, Asset]:
                limiter.acquire()
                return (*self._execute_scan(httpx_plugin, asset, domain), asset)

            with ThreadPoolExecutor(max_workers=self._parallel_workers) as pool:
                futures = {pool.submit(_work, a): a for a in assets}
                for fut in as_completed(futures):
                    try:
                        fnds, raw, fp, asset = fut.result()
                    except Exception:
                        log.exception(
                            "parallel httpx probe failed for %s",
                            futures[fut].identifier,
                        )
                        continue
                    findings.extend(fnds)
                    if raw is not None:
                        records.append(self._scan_record(httpx_plugin.name, asset, raw, fp))
                    if _consider_live(raw):
                        live.append(asset)
        else:
            limiter = RateLimiter(self._rate)
            for asset in assets:
                limiter.acquire()
                fnds, raw, fp = self._execute_scan(httpx_plugin, asset, domain)
                findings.extend(fnds)
                if raw is not None:
                    records.append(self._scan_record(httpx_plugin.name, asset, raw, fp))
                if _consider_live(raw):
                    live.append(asset)

        seen: set[str] = set()
        live_dedup: list[Asset] = []
        for a in live:
            k = a.identifier.lower().strip().rstrip(".")
            if k in seen:
                continue
            seen.add(k)
            live_dedup.append(a)
        return findings, records, live_dedup

    def execute_parallel(
        self,
        domain: str,
        assets: list[Asset],
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        findings: list[Finding] = []
        records: list[dict[str, Any]] = []
        limiter = RateLimiter(self._rate)
        tasks: list[tuple[ScannerPlugin, Asset]] = [
            (p, a) for p in self._plugins for a in self._assets_for_plugin(p, assets)
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
                log.info(
                    "scan skip (already scanned) %s → %s",
                    plugin.name,
                    asset.identifier,
                )
                return
            if self._extra_context.get("waf_skip_aggressive", True):
                if getattr(plugin, "scan_tier", "safe") == "aggressive" and self._host_under_waf(
                    asset
                ):
                    log.info(
                        "scan skip aggressive %s → %s (WAF)",
                        plugin.name,
                        asset.identifier,
                    )
                    return
            log.info("scan start %s → %s", plugin.name, asset.identifier)
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
            log.info(
                "scan done %s → %s (%s findings)",
                plugin.name,
                asset.identifier,
                len(normalized),
            )
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

        coros = [
            _one(p, a) for p in self._plugins for a in self._assets_for_plugin(p, assets)
        ]
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
