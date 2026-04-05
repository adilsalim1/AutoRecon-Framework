from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from recon.core.defaults import (
    DEFAULT_COLLECTION_PROVIDERS,
    DEFAULT_DISCOVERY_PROVIDERS,
    DEFAULT_FFUF_WORDLIST,
    DEFAULT_SCANNING_PLUGINS,
)


def _load_dotenv_files() -> None:
    """Load `.env` from CWD and project root (never commit secrets)."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv()
    root = Path(__file__).resolve().parents[2]
    load_dotenv(root / ".env")


@dataclass
class DiscordWebhooksConfig:
    """
    Discord webhook URLs from environment only (set in `.env`).
    Do not store these in YAML.
    """

    vulnerabilities: str = ""
    tech: str = ""
    ports: str = ""
    assets: str = ""
    critical: str = ""
    secrets: str = ""
    staging: str = ""
    summary: str = ""

    @classmethod
    def from_env(cls) -> DiscordWebhooksConfig:
        return cls(
            vulnerabilities=(os.getenv("DISCORD_WEBHOOK_VULNERABILITIES") or "").strip(),
            tech=(os.getenv("DISCORD_WEBHOOK_TECH") or "").strip(),
            ports=(os.getenv("DISCORD_WEBHOOK_PORTS") or "").strip(),
            assets=(os.getenv("DISCORD_WEBHOOK_ASSETS") or "").strip(),
            critical=(os.getenv("DISCORD_WEBHOOK_CRITICAL") or "").strip(),
            secrets=(os.getenv("DISCORD_WEBHOOK_SECRETS") or "").strip(),
            staging=(os.getenv("DISCORD_WEBHOOK_STAGING") or "").strip(),
            summary=(os.getenv("DISCORD_WEBHOOK_SUMMARY") or "").strip(),
        )

    def url_for(self, channel: str) -> str:
        return (getattr(self, channel, None) or "").strip()

    def any_configured(self) -> bool:
        return any(
            bool(self.url_for(k))
            for k in (
                "vulnerabilities",
                "tech",
                "ports",
                "assets",
                "critical",
                "secrets",
                "staging",
                "summary",
            )
        )


def _parse_optional_positive_int(val: Any) -> int | None:
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _parse_optional_float(val: Any) -> float | None:
    if val is None or val == "":
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


@dataclass
class DiscoveryConfig:
    enabled: bool = True
    expand_subdomains: bool = True
    providers: list[str] = field(default_factory=lambda: list(DEFAULT_DISCOVERY_PROVIDERS))
    timeout_seconds: int = 300
    """Subprocess budget for most discovery CLIs (subfinder, waybackurls, …)."""
    amass_timeout_seconds: int = 1800
    """Passive `amass enum` often exceeds 5–10 minutes; 1800s (30m) avoids exit 124 on large scopes."""
    wordlist: str = ""
    resolvers: str = ""
    single_target_mode: bool = False
    """When True, skip all discovery providers and scan only the hostname or IP in `domain`."""


@dataclass
class CollectionConfig:
    """Passive/active URL harvesters (gau, waybackurls, katana, hakrawler)."""

    enabled: bool = True
    providers: list[str] = field(
        default_factory=lambda: list(DEFAULT_COLLECTION_PROVIDERS)
    )
    timeout_seconds: int = 300
    max_urls_per_host: int = 300
    max_crawl_seeds: int = 15
    linkfinder_script: str = ""
    """Path to LinkFinder `linkfinder.py` for JS endpoint extraction (optional)."""


@dataclass
class ScanningConfig:
    enabled: bool = True
    parallel_workers: int = 4
    rate_limit_per_second: float = 5.0
    plugins: list[str] = field(default_factory=lambda: list(DEFAULT_SCANNING_PLUGINS))
    skip_duplicate_targets: bool = True
    timeout_seconds: int = 300
    ffuf_wordlist: str = DEFAULT_FFUF_WORDLIST
    secretfinder_script: str = ""
    wafw00f_aggressive: bool = True
    live_hosts_only: bool = False
    """When True and httpx_scanner is enabled, run httpx on all assets first; other scanners only see hosts with httpx JSON output (or httpx skipped as duplicate)."""
    vhost_ffuf_wordlist: str = ""
    """Path to vhost wordlist; lines may contain literal %s replaced with the scan apex (see recon/data/wl-vhost.txt)."""
    vhost_ffuf_filter_size: Optional[int] = None
    """If set, ffuf `-fs` to drop the default vhost response size ([ffuf vhost docs](https://github.com/ffuf/ffuf#virtual-host-discovery-without-dns-records))."""
    vhost_ffuf_autocalibrate: bool = True
    """When True and vhost_ffuf_filter_size is unset, pass ffuf `-ac` to auto-calibrate filters."""
    naabu_top_ports: int = 100
    """SYN port scan width for naabu_scanner (`-top-ports`). Use only on authorized targets."""
    nmap_top_ports: int = 50
    """`--top-ports` for nmap_scanner service detection."""
    nmap_scripts: str = ""
    """Optional nmap `--script=` value (e.g. `vuln` or `http-vuln*`). Empty = version scan only (`-sV`)."""
    nmap_scan_timeout_seconds: int = 900
    """Subprocess timeout for nmap_scanner (can be slower than web probes)."""
    js_analysis_enabled: bool = True
    """Fetch collected JS URLs and run regex (+ optional LinkFinder) analysis post-scan."""
    correlation_enabled: bool = True
    risk_scoring_enabled: bool = True
    waf_skip_aggressive: bool = False
    """When True, skip scan_tier=aggressive plugins for hosts in pipeline_runtime.waf_by_host."""
    api_endpoint_priority: bool = True
    """Order phase-2 plugins: wafw00f first, then nuclei, then the rest."""
    max_js_analyze: int = 40
    url_secret_scan_max: int = 500
    """Regex secret scan across collected URL strings (lightweight)."""


@dataclass
class AlertsConfig:
    webhook_url: str = ""
    min_severity: str = "high"
    batch_summaries: bool = True
    deduplicate: bool = True
    discord_rich_embeds: bool = True
    """If webhook host is Discord, send embed-style payloads."""
    alert_waf_detection: bool = True
    """Always include WAF findings in alert batches (subject to min_severity unless elevated)."""
    min_risk_score: float | None = None
    """If set, drop findings with risk_score below this threshold from notifications."""
    discord_use_env_webhooks: bool = True
    """When True and any `DISCORD_WEBHOOK_*` env var is set, use multi-channel Discord notifier."""
    discord_webhooks: DiscordWebhooksConfig = field(default_factory=DiscordWebhooksConfig)
    """Populated from environment in `from_dict` — not read from YAML."""
    discord_http_retries: int = 3
    discord_http_timeout_seconds: float = 35.0
    discord_staging_batch_max: int = 30


@dataclass
class ExecutionConfig:
    mode: str = "sequential"  # sequential | async
    max_retries: int = 3
    retry_backoff_seconds: float = 1.0


@dataclass
class StorageConfig:
    backend: str = "json"
    output_dir: str = "output"


@dataclass
class BootstrapConfig:
    """Optional automatic installation of external CLI dependencies."""

    auto_install: bool = True
    """When true, missing tools required by enabled plugins/providers are installed (Go, pip, apt on Debian)."""


@dataclass
class AppConfig:
    domain: str = ""
    stream_subprocess_output: bool = True
    """Echo external tool stdout/stderr to the console while capturing for parsers."""
    tool_paths: dict[str, str] = field(default_factory=dict)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    collection: CollectionConfig = field(default_factory=CollectionConfig)
    scanning: ScanningConfig = field(default_factory=ScanningConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    bootstrap: BootstrapConfig = field(default_factory=BootstrapConfig)
    log_level: str = "INFO"
    log_json: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppConfig:
        d = data.get("discovery", {}) or {}
        col = data.get("collection", {}) or {}
        s = data.get("scanning", {}) or {}
        a = data.get("alerts", {}) or {}
        e = data.get("execution", {}) or {}
        st = data.get("storage", {}) or {}
        boot = data.get("bootstrap", {}) or {}
        tools = data.get("tools") or {}
        tool_paths: dict[str, str] = {}
        if isinstance(tools, dict):
            tool_paths = {str(k): str(v) for k, v in tools.items() if v is not None}
        prov = d.get("providers")
        if prov is None:
            prov_list = list(DEFAULT_DISCOVERY_PROVIDERS)
        elif isinstance(prov, list):
            prov_list = [str(x).strip() for x in prov if str(x).strip()]
            if not prov_list:
                prov_list = list(DEFAULT_DISCOVERY_PROVIDERS)
        else:
            prov_list = list(DEFAULT_DISCOVERY_PROVIDERS)
        spl = s.get("plugins")
        if spl is None:
            plug_list = list(DEFAULT_SCANNING_PLUGINS)
        elif isinstance(spl, list):
            plug_list = [str(x).strip() for x in spl if str(x).strip()]
            if not plug_list:
                plug_list = list(DEFAULT_SCANNING_PLUGINS)
        else:
            plug_list = list(DEFAULT_SCANNING_PLUGINS)
        col_prov = col.get("providers")
        if col_prov is None:
            col_list = list(DEFAULT_COLLECTION_PROVIDERS)
        elif isinstance(col_prov, list):
            col_list = [str(x).strip() for x in col_prov if str(x).strip()]
            if not col_list:
                col_list = list(DEFAULT_COLLECTION_PROVIDERS)
        else:
            col_list = list(DEFAULT_COLLECTION_PROVIDERS)
        cfg = cls(
            domain=data.get("domain", ""),
            stream_subprocess_output=bool(data.get("stream_subprocess_output", True)),
            tool_paths=tool_paths,
            discovery=DiscoveryConfig(
                enabled=d.get("enabled", True),
                expand_subdomains=d.get("expand_subdomains", True),
                providers=prov_list,
                timeout_seconds=int(d.get("timeout_seconds", 300)),
                amass_timeout_seconds=max(
                    60, int(d.get("amass_timeout_seconds", 1800))
                ),
                wordlist=str(d.get("wordlist", "") or ""),
                resolvers=str(d.get("resolvers", "") or ""),
                single_target_mode=bool(d.get("single_target_mode", False)),
            ),
            collection=CollectionConfig(
                enabled=bool(col.get("enabled", True)),
                providers=col_list,
                timeout_seconds=int(col.get("timeout_seconds", 300)),
                max_urls_per_host=int(col.get("max_urls_per_host", 300)),
                max_crawl_seeds=int(col.get("max_crawl_seeds", 15)),
                linkfinder_script=str(col.get("linkfinder_script", "") or ""),
            ),
            scanning=ScanningConfig(
                enabled=s.get("enabled", True),
                parallel_workers=int(s.get("parallel_workers", 4)),
                rate_limit_per_second=float(s.get("rate_limit_per_second", 5)),
                plugins=plug_list,
                skip_duplicate_targets=s.get("skip_duplicate_targets", True),
                timeout_seconds=int(s.get("timeout_seconds", 300)),
                ffuf_wordlist=(
                    str(s.get("ffuf_wordlist", "") or "").strip() or DEFAULT_FFUF_WORDLIST
                ),
                secretfinder_script=str(s.get("secretfinder_script", "") or ""),
                wafw00f_aggressive=bool(s.get("wafw00f_aggressive", True)),
                live_hosts_only=bool(s.get("live_hosts_only", False)),
                vhost_ffuf_wordlist=str(s.get("vhost_ffuf_wordlist", "") or ""),
                vhost_ffuf_filter_size=_parse_optional_positive_int(
                    s.get("vhost_ffuf_filter_size")
                ),
                vhost_ffuf_autocalibrate=bool(s.get("vhost_ffuf_autocalibrate", True)),
                naabu_top_ports=int(s.get("naabu_top_ports", 100)),
                nmap_top_ports=int(s.get("nmap_top_ports", 50)),
                nmap_scripts=str(s.get("nmap_scripts", "") or ""),
                nmap_scan_timeout_seconds=int(s.get("nmap_scan_timeout_seconds", 900)),
                js_analysis_enabled=bool(s.get("js_analysis_enabled", True)),
                correlation_enabled=bool(s.get("correlation_enabled", True)),
                risk_scoring_enabled=bool(s.get("risk_scoring_enabled", True)),
                waf_skip_aggressive=bool(s.get("waf_skip_aggressive", False)),
                api_endpoint_priority=bool(s.get("api_endpoint_priority", True)),
                max_js_analyze=int(s.get("max_js_analyze", 40)),
                url_secret_scan_max=int(s.get("url_secret_scan_max", 500)),
            ),
            alerts=AlertsConfig(
                webhook_url=a.get("webhook_url", "") or "",
                min_severity=a.get("min_severity", "high"),
                batch_summaries=a.get("batch_summaries", True),
                deduplicate=a.get("deduplicate", True),
                discord_rich_embeds=bool(a.get("discord_rich_embeds", True)),
                alert_waf_detection=bool(a.get("alert_waf_detection", True)),
                min_risk_score=_parse_optional_float(a.get("min_risk_score")),
                discord_use_env_webhooks=bool(a.get("discord_use_env_webhooks", True)),
                discord_http_retries=int(a.get("discord_http_retries", 3)),
                discord_http_timeout_seconds=float(
                    a.get("discord_http_timeout_seconds", 35.0)
                ),
                discord_staging_batch_max=int(a.get("discord_staging_batch_max", 30)),
            ),
            execution=ExecutionConfig(
                mode=e.get("mode", "sequential"),
                max_retries=int(e.get("max_retries", 3)),
                retry_backoff_seconds=float(e.get("retry_backoff_seconds", 1.0)),
            ),
            storage=StorageConfig(
                backend=st.get("backend", "json"),
                output_dir=st.get("output_dir", "output"),
            ),
            bootstrap=BootstrapConfig(
                auto_install=boot.get("auto_install", True),
            ),
            log_level=data.get("log_level", "INFO"),
            log_json=data.get("log_json", False),
        )
        cfg.alerts.discord_webhooks = DiscordWebhooksConfig.from_env()
        return cfg


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _env_overrides() -> dict[str, Any]:
    """Map RECON_* environment variables to nested config keys."""
    keys = [
        ("RECON_DOMAIN", ("domain",)),
        ("RECON_LOG_LEVEL", ("log_level",)),
        ("RECON_WEBHOOK_URL", ("alerts", "webhook_url")),
        ("RECON_ALERT_MIN_SEVERITY", ("alerts", "min_severity")),
        ("RECON_SCAN_RATE", ("scanning", "rate_limit_per_second")),
        ("RECON_SCAN_WORKERS", ("scanning", "parallel_workers")),
        ("RECON_EXECUTION_MODE", ("execution", "mode")),
        ("RECON_OUTPUT_DIR", ("storage", "output_dir")),
    ]
    patch: dict[str, Any] = {}
    for env_key, path in keys:
        val = os.environ.get(env_key)
        if val is None or val == "":
            continue
        cur = patch
        for p in path[:-1]:
            cur = cur.setdefault(p, {})
        leaf = path[-1]
        if leaf in ("rate_limit_per_second", "parallel_workers", "max_retries"):
            try:
                cur[leaf] = float(val) if "." in val else int(val)
            except ValueError:
                cur[leaf] = val
        else:
            cur[leaf] = val
    std = os.environ.get("RECON_SINGLE_DOMAIN", "").strip().lower()
    if std in ("1", "true", "yes", "on"):
        patch.setdefault("discovery", {})["single_target_mode"] = True
    return patch


def _load_config_file(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as e:
            raise ImportError(
                "YAML config requires PyYAML: pip install pyyaml"
            ) from e
        loaded = yaml.safe_load(text) or {}
    elif suffix == ".json":
        loaded = json.loads(text) if text.strip() else {}
    else:
        raise ValueError(f"Unsupported config format: {path.suffix}")
    if not isinstance(loaded, dict):
        raise ValueError("Config root must be a mapping")
    return loaded


def load_config(path: Path | None = None, cli_overrides: dict[str, Any] | None = None) -> AppConfig:
    _load_dotenv_files()
    data: dict[str, Any] = {}
    if path and path.is_file():
        data = _load_config_file(path)
    data = _deep_merge(data, _env_overrides())
    if cli_overrides:
        data = _deep_merge(data, cli_overrides)
    return AppConfig.from_dict(data)
