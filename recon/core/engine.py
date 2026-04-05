from __future__ import annotations

import asyncio
import ipaddress
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
from recon.modules.correlation import correlate_findings
from recon.modules.js_analysis import JsAnalysisEngine
from recon.modules.discord_router import is_critical_host_asset, is_staging_triage_asset
from recon.modules.notifier import (
    DiscordMultiChannelNotifier,
    WebhookNotifier,
    use_discord_multi_channel,
)
from recon.modules.risk_scoring import apply_risk_scores
from recon.modules.scan_workflow import order_full_scanning_plugins, order_phase2_plugins
from recon.modules.scanning import ScanEngine
from recon.modules.secrets.detector import SecretDetector
from recon.modules.storage import JsonStorageBackend, StorageBackend
from recon.modules.url_collection import UrlCollectionResult, UrlCollectionService
from recon.plugins.registry import PluginRegistry, load_builtin_plugins

log = get_logger("engine")


def _asset_from_single_target(raw: str) -> Asset:
    """One synthetic asset for `discovery.single_target_mode` (hostname, subdomain label, or IP)."""
    s = raw.strip()
    if not s:
        raise ValueError("single-target domain is empty")
    try:
        ipaddress.ip_address(s)
        return Asset(
            identifier=s,
            asset_type=AssetType.IP,
            parent_domain=s,
            metadata={"source": "single_target"},
        )
    except ValueError:
        pass
    h = s.lower().rstrip(".")
    parts = [p for p in h.split(".") if p]
    at = AssetType.DOMAIN if len(parts) == 2 else AssetType.SUBDOMAIN
    return Asset(
        identifier=h,
        asset_type=at,
        parent_domain=h,
        metadata={"source": "single_target"},
    )


def _apex_assets_for_vhost_scan(domain: str, analyzed: list[Asset]) -> list[Asset]:
    """
    vhost_ffuf_scanner runs only against the root/apex domain (one target per run).
    Reuse a discovered apex asset if present; otherwise synthesize a DOMAIN asset.
    """
    raw = domain.strip()
    if not raw:
        return []
    apex = raw.lower().rstrip(".")
    for a in analyzed:
        if a.identifier.lower().strip().rstrip(".") == apex:
            return [a]
    return [
        Asset(
            identifier=raw,
            asset_type=AssetType.DOMAIN,
            parent_domain=raw,
            metadata={"source": "vhost_ffuf_apex_only"},
        )
    ]


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
            log.info(
                "discovery start domain=%s providers=%s single_target=%s",
                dom,
                self.config.discovery.providers,
                self.config.discovery.single_target_mode,
            )
            if self.config.discovery.single_target_mode:
                assets = [_asset_from_single_target(dom)]
                log.info("single-target mode: skipped passive discovery (%s asset(s))", len(assets))
            elif not self.config.discovery.enabled:
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

        log.info("discovery complete raw_assets=%s", len(assets))

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

        self._notify_discord_post_analysis(result, run_id, dom, analyzed)

        pipeline_runtime: dict[str, Any] = {"waf_by_host": {}}
        collection_result: UrlCollectionResult | None = None
        if self.config.collection.enabled:
            try:
                coll_svc = UrlCollectionService(
                    providers=self.config.collection.providers,
                    timeout_seconds=self.config.collection.timeout_seconds,
                    max_urls_per_host=self.config.collection.max_urls_per_host,
                    max_crawl_seeds=self.config.collection.max_crawl_seeds,
                    stream_subprocess_output=self.config.stream_subprocess_output,
                )
                collection_result = self._retry(
                    "url_collection",
                    lambda: coll_svc.collect(
                        dom, analyzed, dict(self.config.tool_paths)
                    ),
                )
                pipeline_runtime["high_value_paths"] = (
                    collection_result.endpoint_paths[:500]
                )
                pipeline_runtime["collection_summary"] = (
                    collection_result.to_serializable()
                )
                if isinstance(self._storage, JsonStorageBackend):
                    self._storage.save_json_artifact(
                        run_id,
                        "url_collection",
                        {
                            **collection_result.to_serializable(),
                            "urls_sample": collection_result.urls[:2000],
                            "js_urls": collection_result.js_urls,
                        },
                    )
            except Exception as e:
                result.errors.append(f"url_collection: {e}")
                log.exception("url collection failed")

        # 3) Scanning
        findings: list[Finding] = []
        scan_records: list[dict[str, Any]] = []
        if scan_profile == "none" or not self.config.scanning.enabled:
            log.info("scanning skipped (profile or config)")
        else:
            try:
                plugin_names = list(self.config.scanning.plugins)
                plugins = self._registry.resolve(plugin_names)
                api_pri = self.config.scanning.api_endpoint_priority and (
                    any(a.asset_type == AssetType.API for a in analyzed)
                    or bool(pipeline_runtime.get("high_value_paths"))
                )
                plugins = order_full_scanning_plugins(
                    plugins, api_endpoint_priority=api_pri
                )
                log.info(
                    "scanning stage: %s assets × %s plugins [%s]",
                    len(analyzed),
                    len(plugins),
                    ", ".join(p.name for p in plugins),
                )
            except KeyError as e:
                result.errors.append(f"plugin resolution: {e}")
                findings = self._post_scan_enrichment(
                    findings, analyzed, dom, collection_result
                )
                result.findings = findings
                self._storage.save_findings(run_id, findings)
                self._finalize_notifications(result, findings, run_id, dom)
                return result

            scan_ctx = {
                "tool_paths": dict(self.config.tool_paths),
                "scan_timeout_seconds": self.config.scanning.timeout_seconds,
                "ffuf_wordlist": self.config.scanning.ffuf_wordlist,
                "vhost_ffuf_wordlist": self.config.scanning.vhost_ffuf_wordlist,
                "vhost_ffuf_filter_size": self.config.scanning.vhost_ffuf_filter_size,
                "vhost_ffuf_autocalibrate": self.config.scanning.vhost_ffuf_autocalibrate,
                "vhost_scan_assets": _apex_assets_for_vhost_scan(dom, analyzed),
                "secretfinder_script": self.config.scanning.secretfinder_script,
                "wafw00f_aggressive": self.config.scanning.wafw00f_aggressive,
                "naabu_top_ports": self.config.scanning.naabu_top_ports,
                "nmap_top_ports": self.config.scanning.nmap_top_ports,
                "nmap_scripts": self.config.scanning.nmap_scripts,
                "nmap_scan_timeout_seconds": self.config.scanning.nmap_scan_timeout_seconds,
                "stream_subprocess_output": self.config.stream_subprocess_output,
                "pipeline_runtime": pipeline_runtime,
                "waf_skip_aggressive": self.config.scanning.waf_skip_aggressive,
            }
            httpx_plugin = next((p for p in plugins if p.name == "httpx_scanner"), None)
            other_plugins = order_phase2_plugins(
                [p for p in plugins if p.name != "httpx_scanner"],
                api_endpoint_priority=api_pri,
            )
            live_only = self.config.scanning.live_hosts_only
            # "Alive" = httpx reported ≥1 JSON line (web-reachable). Port scanners (naabu/nmap, etc.)
            # must use this partition when live_hosts_only is true — even if httpx_scanner is omitted
            # from plugins, we still run httpx once as an implicit probe.
            httpx_for_probe = httpx_plugin
            if live_only and len(other_plugins) > 0 and httpx_for_probe is None:
                try:
                    httpx_for_probe = self._registry.get("httpx_scanner")
                except KeyError:
                    httpx_for_probe = None
            use_two_phase = (
                live_only
                and httpx_for_probe is not None
                and len(other_plugins) > 0
            )

            if use_two_phase:
                if httpx_plugin is None:
                    log.info(
                        "scanning: live_hosts_only — implicit httpx probe, then [%s] on httpx-live hosts only",
                        ", ".join(p.name for p in other_plugins),
                    )
                else:
                    log.info(
                        "scanning: live_hosts_only — httpx on all assets, then [%s] on live hosts only",
                        ", ".join(p.name for p in other_plugins),
                    )

            def _scan_engine_kwargs() -> dict[str, Any]:
                return {
                    "parallel_workers": self.config.scanning.parallel_workers,
                    "rate_limit_per_second": self.config.scanning.rate_limit_per_second,
                    "skip_duplicates": self.config.scanning.skip_duplicate_targets,
                    "has_fingerprint": self._storage.has_scan_fingerprint,
                    "record_fingerprint": self._storage.record_scan_fingerprint,
                    "extra_context": scan_ctx,
                }

            try:
                if use_two_phase:
                    kw = _scan_engine_kwargs()
                    probe_engine = ScanEngine(plugins=[httpx_for_probe], **kw)
                    use_parallel = (
                        scan_profile == "full"
                        and self.config.scanning.parallel_workers > 1
                    )

                    def _phase1() -> tuple[list[Finding], list[dict[str, Any]], list[Asset]]:
                        return probe_engine.httpx_probe_partition(
                            dom,
                            analyzed,
                            httpx_for_probe,
                            parallel=use_parallel,
                        )

                    f1, r1, live_assets = self._retry("scanning", _phase1)
                    log.info(
                        "httpx probe: %s live host(s) of %s asset(s)",
                        len(live_assets),
                        len(analyzed),
                    )
                    rest_engine = ScanEngine(plugins=other_plugins, **kw)

                    def _phase2() -> tuple[list[Finding], list[dict[str, Any]]]:
                        if self.config.execution.mode == "async":
                            return asyncio.run(rest_engine.execute_async(dom, live_assets))
                        if scan_profile == "full" and self.config.scanning.parallel_workers > 1:
                            return rest_engine.execute_parallel(dom, live_assets)
                        return rest_engine.execute_sequential(dom, live_assets)

                    f2, r2 = self._retry("scanning", _phase2)
                    findings = f1 + f2
                    scan_records = r1 + r2
                else:
                    if live_only and len(other_plugins) > 0 and httpx_for_probe is None:
                        log.warning(
                            "live_hosts_only is true but httpx probe is unavailable — "
                            "running non-httpx scanners on all assets"
                        )
                    engine = ScanEngine(plugins=plugins, **_scan_engine_kwargs())
                    if self.config.execution.mode == "async":
                        findings, scan_records = asyncio.run(
                            engine.execute_async(dom, analyzed)
                        )
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

        self._apply_waf_asset_tags(analyzed, pipeline_runtime.get("waf_by_host", {}))
        self._storage.save_assets(run_id, analyzed)

        findings = self._post_scan_enrichment(
            findings, analyzed, dom, collection_result
        )
        result.findings = findings
        self._storage.save_findings(run_id, findings)
        for rec in scan_records:
            self._storage.append_scan_record(run_id, rec)

        self._finalize_notifications(result, findings, run_id, dom)
        return result

    @staticmethod
    def _apply_waf_asset_tags(assets: list[Asset], waf_by_host: Any) -> None:
        if not isinstance(waf_by_host, dict):
            return
        for a in assets:
            k = a.identifier.lower().strip().rstrip(".")
            if k not in waf_by_host:
                continue
            a.metadata["waf_protected"] = True
            a.metadata["waf_vendor"] = waf_by_host[k]

    def _post_scan_enrichment(
        self,
        findings: list[Finding],
        analyzed: list[Asset],
        dom: str,
        collection_result: UrlCollectionResult | None,
    ) -> list[Finding]:
        out = list(findings)
        if collection_result and self.config.scanning.url_secret_scan_max > 0:
            det = SecretDetector()
            out.extend(
                det.scan_urls(
                    collection_result.urls,
                    max_urls=self.config.scanning.url_secret_scan_max,
                    source_scanner="url_secret_detector",
                )
            )
        if collection_result and self.config.scanning.js_analysis_enabled:
            jn = JsAnalysisEngine(
                max_js_urls=self.config.scanning.max_js_analyze,
                stream_subprocess_output=self.config.stream_subprocess_output,
            )
            lf = (self.config.collection.linkfinder_script or "").strip()
            out.extend(
                jn.analyze(
                    collection_result.js_urls,
                    linkfinder_script=lf,
                    parent_domain=dom,
                )
            )
        if self.config.scanning.correlation_enabled:
            out = correlate_findings(out, analyzed)
        if self.config.scanning.risk_scoring_enabled:
            out = apply_risk_scores(out, analyzed)
        return out

    def _notify_discord_post_analysis(
        self,
        result: PipelineResult,
        run_id: str,
        dom: str,
        analyzed: list[Asset],
    ) -> None:
        if not use_discord_multi_channel(self.config):
            return
        try:
            dn = DiscordMultiChannelNotifier.from_config(self.config)
            dn.send_asset_discovery(analyzed, run_id, dom)
            for a in analyzed:
                if is_critical_host_asset(a):
                    dn.send_critical_subdomain(a, run_id, dom)
            staging = [a for a in analyzed if is_staging_triage_asset(a)]
            if staging:
                dn.send_staging_batch(staging, run_id, dom)
        except Exception as e:
            result.errors.append(f"discord_post_analysis: {e}")
            log.exception("discord post-analysis notifications failed")

    def _finalize_notifications(
        self,
        result: PipelineResult,
        findings: list[Finding],
        run_id: str,
        dom: str,
    ) -> None:
        try:
            if use_discord_multi_channel(self.config):
                dn = DiscordMultiChannelNotifier.from_config(self.config)
                dn.process_scan_findings(findings, run_id, dom)
                dn.flush_all_buffers()
                dn.send_summary(
                    {
                        "errors": len(result.errors),
                        "findings_total": len(findings),
                    },
                    run_id,
                    dom,
                    total_assets=len(result.assets),
                    findings=findings,
                )
            elif self.config.alerts.webhook_url:
                min_sev = _parse_severity(self.config.alerts.min_severity)
                notifier = WebhookNotifier(
                    webhook_url=self.config.alerts.webhook_url,
                    min_severity=min_sev,
                    batch_summaries=self.config.alerts.batch_summaries,
                    deduplicate=self.config.alerts.deduplicate,
                    discord_rich_embeds=self.config.alerts.discord_rich_embeds,
                    alert_waf_detection=self.config.alerts.alert_waf_detection,
                    min_risk_score=self.config.alerts.min_risk_score,
                )
                notifier.notify(
                    findings,
                    run_id=run_id,
                    domain=dom,
                    total_assets=len(result.assets),
                )
            else:
                log.info("alerts: no Discord env webhooks and no alerts.webhook_url; skipping")
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
