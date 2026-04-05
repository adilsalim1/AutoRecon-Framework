from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from recon.core.config_loader import AppConfig
from recon.core.discovery_factory import build_discovery
from recon.core.logger import get_logger
from recon.models.assets import Asset, AssetType
from recon.models.findings import Finding, Severity
from recon.modules.analysis import AssetAnalyzer
from recon.modules.discovery import DiscoveryProvider
from recon.modules.notifier import WebhookNotifier
from recon.modules.scanning import ScanEngine
from recon.modules.storage import JsonStorageBackend, StorageBackend
from recon.plugins.registry import PluginRegistry, load_builtin_plugins

log = get_logger("engine")


@dataclass
class PipelineResult:
    run_id: str
    domain: str
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class PipelineEngine:
    """
    Orchestrates discovery → analysis → scanning → storage → notification
    with retries and per-stage failure isolation.
    """

    def __init__(
        self,
        config: AppConfig,
        discovery: DiscoveryProvider | None = None,
        registry: PluginRegistry | None = None,
        storage: StorageBackend | None = None,
    ) -> None:
        self.config = config
        self._discovery = discovery if discovery is not None else build_discovery(config)
        self._registry = registry or load_builtin_plugins()
        out = Path(config.storage.output_dir)
        if not out.is_absolute():
            out = Path.cwd() / out
        self._storage = storage or JsonStorageBackend(out)

    def _retry(self, name: str, fn: Callable[[], Any]) -> Any:
        last: Exception | None = None
        for attempt in range(1, self.config.execution.max_retries + 1):
            try:
                return fn()
            except Exception as e:
                last = e
                log.warning("stage %s attempt %s failed: %s", name, attempt, e)
                time.sleep(self.config.execution.retry_backoff_seconds * attempt)
        msg = f"{name} failed after retries: {last}"
        log.error(msg)
        raise RuntimeError(msg) from last

    def run(
        self,
        domain: str | None = None,
        scan_profile: str = "full",
    ) -> PipelineResult:
        dom = (domain or self.config.domain or "").strip()
        if not dom:
            raise ValueError("domain is required (CLI or config)")

        run_id = str(uuid.uuid4())[:8]
        result = PipelineResult(run_id=run_id, domain=dom)

        # 1) Discovery
        try:
            if not self.config.discovery.enabled:
                assets = [
                    Asset(
                        identifier=dom,
                        asset_type=AssetType.DOMAIN,
                        parent_domain=dom,
                        metadata={"source": "discovery_disabled"},
                    )
                ]
            else:
                assets = self._retry(
                    "discovery",
                    lambda: self._discovery.discover(
                        dom,
                        expand_subdomains=self.config.discovery.expand_subdomains,
                    ),
                )
        except Exception as e:
            result.errors.append(str(e))
            return result

        # 2) Analysis
        try:
            analyzer = AssetAnalyzer()
            analyzed = self._retry("analysis", lambda: analyzer.analyze(assets))
        except Exception as e:
            result.errors.append(str(e))
            return result

        result.assets = analyzed
        self._storage.save_assets(run_id, analyzed)
        log.info(
            "analysis complete: %s assets priority=%s",
            len(analyzed),
            analyzer.summarize_by_priority(analyzed),
        )

        # 3) Scanning
        findings: list[Finding] = []
        scan_records: list[dict[str, Any]] = []
        if scan_profile == "none" or not self.config.scanning.enabled:
            log.info("scanning skipped (profile or config)")
        else:
            try:
                plugin_names = list(self.config.scanning.plugins)
                plugins = self._registry.resolve(plugin_names)
            except KeyError as e:
                result.errors.append(f"plugin resolution: {e}")
                self._finalize_notifications(result, findings, run_id, dom)
                return result

            scan_ctx = {
                "tool_paths": dict(self.config.tool_paths),
                "scan_timeout_seconds": self.config.scanning.timeout_seconds,
                "ffuf_wordlist": self.config.scanning.ffuf_wordlist,
                "secretfinder_script": self.config.scanning.secretfinder_script,
                "wafw00f_aggressive": self.config.scanning.wafw00f_aggressive,
            }
            engine = ScanEngine(
                plugins=plugins,
                parallel_workers=self.config.scanning.parallel_workers,
                rate_limit_per_second=self.config.scanning.rate_limit_per_second,
                skip_duplicates=self.config.scanning.skip_duplicate_targets,
                has_fingerprint=self._storage.has_scan_fingerprint,
                record_fingerprint=self._storage.record_scan_fingerprint,
                extra_context=scan_ctx,
            )

            try:
                if self.config.execution.mode == "async":
                    findings, scan_records = asyncio.run(engine.execute_async(dom, analyzed))
                elif scan_profile == "full" and self.config.scanning.parallel_workers > 1:
                    findings, scan_records = self._retry(
                        "scanning",
                        lambda: engine.execute_parallel(dom, analyzed),
                    )
                else:
                    findings, scan_records = self._retry(
                        "scanning",
                        lambda: engine.execute_sequential(dom, analyzed),
                    )
            except Exception as e:
                result.errors.append(f"scanning: {e}")
                log.exception("scanning stage failed")

        result.findings = findings
        self._storage.save_findings(run_id, findings)
        for rec in scan_records:
            self._storage.append_scan_record(run_id, rec)

        self._finalize_notifications(result, findings, run_id, dom)
        return result

    def _finalize_notifications(
        self,
        result: PipelineResult,
        findings: list[Finding],
        run_id: str,
        dom: str,
    ) -> None:
        min_sev = _parse_severity(self.config.alerts.min_severity)
        notifier = WebhookNotifier(
            webhook_url=self.config.alerts.webhook_url,
            min_severity=min_sev,
            batch_summaries=self.config.alerts.batch_summaries,
            deduplicate=self.config.alerts.deduplicate,
        )
        try:
            notifier.notify(findings, run_id=run_id, domain=dom)
        except Exception as e:
            result.errors.append(f"notify: {e}")
            log.exception("notification failed")

        log.info(
            "pipeline %s complete: assets=%s findings=%s errors=%s",
            run_id,
            len(result.assets),
            len(result.findings),
            len(result.errors),
        )


def _parse_severity(s: str) -> Severity:
    try:
        return Severity(s.lower())
    except ValueError:
        return Severity.HIGH
