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
from recon.modules.surface_inventory import (
    build_surface_inventory,
    extend_inventory_with_finding_hosts,
    httpx_target_lines,
    live_hosts_from_httpx_findings,
    normalize_host,
)
from recon.plugins.base import ScanContext
from recon.plugins.tool_scanners import HttpxScannerPlugin, httpx_multiline_probe
from recon.modules.storage import JsonStorageBackend, StorageBackend
from recon.modules.url_collection import UrlCollectionResult, UrlCollectionService
from recon.plugins.registry import PluginRegistry, load_builtin_plugins

log = get_logger("engine")

_SCAN_PHASE_ENUM = frozenset({"vhost_ffuf_scanner", "ffuf_scanner"})
_SCAN_PHASE_TECH = frozenset({"whatweb_scanner", "wappalyzer_scanner", "wafw00f_scanner"})
_SCAN_PHASE_VULN = frozenset(
    {"nuclei_scanner", "subjack_scanner", "subzy_scanner", "secretfinder_scanner"}
)
_SCAN_PHASE_PORTS = frozenset({"naabu_scanner", "nmap_scanner"})
_SCAN_PHASED = (
    _SCAN_PHASE_ENUM
    | _SCAN_PHASE_TECH
    | _SCAN_PHASE_VULN
    | _SCAN_PHASE_PORTS
    | frozenset({"httpx_scanner"})
)


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
                "collection_js_urls": (
                    list(collection_result.js_urls) if collection_result else []
                ),
                "secretfinder_max_js_urls": int(
                    self.config.scanning.secretfinder_max_js_urls
                ),
            }

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
                log.info(
                    "scanning: phased pipeline (enum → inventory → tech/WAF → "
                    "httpx batch → vuln → ports)"
                )
                findings, scan_records = self._run_phased_scanning(
                    result,
                    run_id,
                    dom,
                    analyzed,
                    plugins,
                    api_pri,
                    scan_profile,
                    collection_result,
                    pipeline_runtime,
                    scan_ctx,
                )
            except Exception as e:
                result.errors.append(f"scanning: {e}")
                log.exception("scanning stage failed")

        self._apply_waf_asset_tags(analyzed, pipeline_runtime.get("waf_by_host", {}))
        self._storage.save_assets(run_id, analyzed)

        keys_before_enrich = {f.dedupe_key() for f in findings}
        findings = self._post_scan_enrichment(
            findings, analyzed, dom, collection_result
        )
        result.findings = findings
        self._storage.save_findings(run_id, findings)
        for rec in scan_records:
            self._storage.append_scan_record(run_id, rec)

        if use_discord_multi_channel(self.config):
            try:
                dn = DiscordMultiChannelNotifier.from_config(self.config)
                for f in findings:
                    if f.dedupe_key() not in keys_before_enrich:
                        dn.ingest_scan_finding(f, run_id, dom)
                dn.flush_all_buffers()
            except Exception as e:
                result.errors.append(f"discord_post_enrich: {e}")
                log.exception("discord post-enrichment notifications failed")
        self._finalize_notifications(
            result,
            findings,
            run_id,
            dom,
            skip_findings_ingest=use_discord_multi_channel(self.config),
        )
        return result

    def _execute_scan_phase(
        self,
        engine: ScanEngine,
        dom: str,
        assets: list[Asset],
        scan_profile: str,
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        if self.config.execution.mode == "async":
            return asyncio.run(engine.execute_async(dom, assets))
        if scan_profile == "full" and self.config.scanning.parallel_workers > 1:
            return engine.execute_parallel(dom, assets)
        return engine.execute_sequential(dom, assets)

    def _discord_ingest_findings(
        self, batch: list[Finding], run_id: str, dom: str, result: PipelineResult
    ) -> None:
        if not batch or not use_discord_multi_channel(self.config):
            return
        try:
            dn = DiscordMultiChannelNotifier.from_config(self.config)
            dn.process_scan_findings(batch, run_id, dom)
            dn.flush_all_buffers()
        except Exception as e:
            result.errors.append(f"discord_phase: {e}")
            log.exception("discord phased notification failed")

    def _notify_surface_inventory_phase(
        self,
        result: PipelineResult,
        run_id: str,
        dom: str,
        inventory: dict[str, Any],
        analyzed: list[Asset],
    ) -> None:
        if not use_discord_multi_channel(self.config):
            return
        try:
            dn = DiscordMultiChannelNotifier.from_config(self.config)
            dn.send_surface_inventory(inventory, run_id, dom)
            for a in analyzed:
                if is_critical_host_asset(a):
                    dn.send_critical_subdomain(a, run_id, dom)
            staging = [a for a in analyzed if is_staging_triage_asset(a)]
            if staging:
                dn.send_staging_batch(staging, run_id, dom)
        except Exception as e:
            result.errors.append(f"discord_inventory: {e}")
            log.exception("discord surface inventory failed")

    def _assets_for_live_hosts(
        self, dom: str, hosts: set[str], analyzed: list[Asset]
    ) -> list[Asset]:
        by = {normalize_host(a.identifier): a for a in analyzed}
        out: list[Asset] = []
        seen: set[str] = set()
        for h in sorted(hosts):
            n = normalize_host(h)
            if not n or n in seen:
                continue
            seen.add(n)
            a = by.get(n)
            if a is not None:
                out.append(a)
            else:
                out.append(
                    Asset(
                        identifier=n,
                        asset_type=AssetType.SUBDOMAIN,
                        parent_domain=dom,
                        metadata={"source": "live_http"},
                    )
                )
        return out

    def _run_phased_scanning(
        self,
        result: PipelineResult,
        run_id: str,
        dom: str,
        analyzed: list[Asset],
        plugins: list[Any],
        api_pri: bool,
        scan_profile: str,
        collection_result: UrlCollectionResult | None,
        pipeline_runtime: dict[str, Any],
        scan_ctx: dict[str, Any],
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        findings: list[Finding] = []
        scan_records: list[dict[str, Any]] = []

        def _kw() -> dict[str, Any]:
            return {
                "parallel_workers": self.config.scanning.parallel_workers,
                "rate_limit_per_second": self.config.scanning.rate_limit_per_second,
                "skip_duplicates": self.config.scanning.skip_duplicate_targets,
                "has_fingerprint": self._storage.has_scan_fingerprint,
                "record_fingerprint": self._storage.record_scan_fingerprint,
                "extra_context": scan_ctx,
            }

        kw = _kw()
        enum_plugins = [p for p in plugins if p.name in _SCAN_PHASE_ENUM]
        if enum_plugins:
            eng = ScanEngine(plugins=enum_plugins, **kw)

            def _enum() -> tuple[list[Finding], list[dict[str, Any]]]:
                return self._execute_scan_phase(eng, dom, analyzed, scan_profile)

            ef, er = self._retry("scanning_enumeration", _enum)
            findings.extend(ef)
            scan_records.extend(er)

        inventory = build_surface_inventory(dom, analyzed, collection_result)
        extend_inventory_with_finding_hosts(inventory, findings)
        pipeline_runtime["surface_inventory"] = {
            "domains_count": inventory.get("domains_count"),
            "urls_count": inventory.get("urls_count"),
            "endpoints_count": inventory.get("endpoints_count"),
        }
        if isinstance(self._storage, JsonStorageBackend):
            self._storage.save_json_artifact(
                run_id,
                "surface_inventory",
                {
                    "apex": inventory.get("apex"),
                    "domains": inventory.get("domains"),
                    "domains_count": inventory.get("domains_count"),
                    "urls_count": inventory.get("urls_count"),
                    "endpoint_paths": inventory.get("endpoint_paths"),
                    "endpoints_count": inventory.get("endpoints_count"),
                    "urls_sample": (inventory.get("urls") or [])[:500],
                },
            )
        self._notify_surface_inventory_phase(result, run_id, dom, inventory, analyzed)

        tech_plugins = order_phase2_plugins(
            [p for p in plugins if p.name in _SCAN_PHASE_TECH],
            api_endpoint_priority=False,
        )
        if tech_plugins:
            eng = ScanEngine(plugins=tech_plugins, **kw)

            def _tech() -> tuple[list[Finding], list[dict[str, Any]]]:
                return self._execute_scan_phase(eng, dom, analyzed, scan_profile)

            tf, tr = self._retry("scanning_tech", _tech)
            findings.extend(tf)
            scan_records.extend(tr)
            self._discord_ingest_findings(tf, run_id, dom, result)

        httpx_plugin = next((p for p in plugins if p.name == "httpx_scanner"), None)
        if httpx_plugin is None and self.config.scanning.live_hosts_only:
            try:
                httpx_plugin = self._registry.get("httpx_scanner")
            except KeyError:
                httpx_plugin = None
        hf: list[Finding] = []
        if httpx_plugin:
            max_u = int(self.config.scanning.max_httpx_targets or 0)
            lines = httpx_target_lines(inventory, max_urls=max_u)
            probe_ctx = ScanContext(
                domain=dom,
                rate_limit_per_second=self.config.scanning.rate_limit_per_second,
                metadata=dict(scan_ctx),
            )
            raw = httpx_multiline_probe(lines, probe_ctx)
            hf = HttpxScannerPlugin().parse(raw)
            findings.extend(hf)
            scan_records.append(
                {
                    "scanner": "httpx_scanner",
                    "mode": "batch",
                    "result_lines": len(hf),
                }
            )
            self._discord_ingest_findings(hf, run_id, dom, result)

        live_hosts = live_hosts_from_httpx_findings(hf) if hf else set()
        if httpx_plugin and live_hosts:
            nuclei_assets = self._assets_for_live_hosts(dom, live_hosts, analyzed)
        else:
            nuclei_assets = list(analyzed)
        port_assets = (
            nuclei_assets if self.config.scanning.live_hosts_only else analyzed
        )

        vuln_plugins = order_phase2_plugins(
            [p for p in plugins if p.name in _SCAN_PHASE_VULN],
            api_endpoint_priority=api_pri,
        )
        if vuln_plugins:
            eng = ScanEngine(plugins=vuln_plugins, **kw)

            def _vuln() -> tuple[list[Finding], list[dict[str, Any]]]:
                return self._execute_scan_phase(eng, dom, nuclei_assets, scan_profile)

            vf, vr = self._retry("scanning_vuln", _vuln)
            findings.extend(vf)
            scan_records.extend(vr)
            self._discord_ingest_findings(vf, run_id, dom, result)

        port_plugins = [p for p in plugins if p.name in _SCAN_PHASE_PORTS]
        if port_plugins:
            eng = ScanEngine(plugins=port_plugins, **kw)

            def _ports() -> tuple[list[Finding], list[dict[str, Any]]]:
                return self._execute_scan_phase(eng, dom, port_assets, scan_profile)

            pf, pr = self._retry("scanning_ports", _ports)
            findings.extend(pf)
            scan_records.extend(pr)
            self._discord_ingest_findings(pf, run_id, dom, result)

        leftover = [p for p in plugins if p.name not in _SCAN_PHASED]
        if leftover:
            eng = ScanEngine(plugins=leftover, **kw)

            def _left() -> tuple[list[Finding], list[dict[str, Any]]]:
                return self._execute_scan_phase(eng, dom, analyzed, scan_profile)

            lf, lr = self._retry("scanning_other", _left)
            findings.extend(lf)
            scan_records.extend(lr)
            self._discord_ingest_findings(lf, run_id, dom, result)

        return findings, scan_records

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
        if collection_result and self.config.scanning.js_snitch_enabled:
            try:
                from recon.modules.js_snitch_runner import run_js_snitch_on_urls

                out.extend(
                    run_js_snitch_on_urls(
                        collection_result.js_urls,
                        tool_paths=dict(self.config.tool_paths),
                        timeout_seconds=self.config.scanning.js_snitch_fetch_timeout_seconds,
                        max_urls=self.config.scanning.js_snitch_max_urls,
                        js_snitch_repo=str(
                            self.config.scanning.js_snitch_repo or ""
                        ).strip(),
                        subprocess_timeout_trufflehog=self.config.scanning.js_snitch_trufflehog_timeout_seconds,
                        subprocess_timeout_semgrep=self.config.scanning.js_snitch_semgrep_timeout_seconds,
                        stream_subprocess_output=self.config.stream_subprocess_output,
                    )
                )
            except Exception as e:
                log.warning("js_snitch: enrichment failed: %s", e)
        if self.config.scanning.correlation_enabled:
            out = correlate_findings(out, analyzed)
        if self.config.scanning.risk_scoring_enabled:
            out = apply_risk_scores(out, analyzed)
        return out

    def _finalize_notifications(
        self,
        result: PipelineResult,
        findings: list[Finding],
        run_id: str,
        dom: str,
        *,
        skip_findings_ingest: bool = False,
    ) -> None:
        try:
            if use_discord_multi_channel(self.config):
                dn = DiscordMultiChannelNotifier.from_config(self.config)
                if not skip_findings_ingest:
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
