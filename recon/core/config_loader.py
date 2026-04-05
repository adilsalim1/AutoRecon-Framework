from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DiscoveryConfig:
    enabled: bool = True
    expand_subdomains: bool = True
    providers: list[str] = field(default_factory=lambda: ["mock"])
    timeout_seconds: int = 300
    wordlist: str = ""
    resolvers: str = ""


@dataclass
class ScanningConfig:
    enabled: bool = True
    parallel_workers: int = 4
    rate_limit_per_second: float = 5.0
    plugins: list[str] = field(default_factory=lambda: ["mock_scanner"])
    skip_duplicate_targets: bool = True
    timeout_seconds: int = 300
    ffuf_wordlist: str = ""
    secretfinder_script: str = ""
    wafw00f_aggressive: bool = False


@dataclass
class AlertsConfig:
    webhook_url: str = ""
    min_severity: str = "high"
    batch_summaries: bool = True
    deduplicate: bool = True


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
    tool_paths: dict[str, str] = field(default_factory=dict)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
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
            prov_list = ["mock"]
        elif isinstance(prov, list):
            prov_list = [str(x).strip() for x in prov if str(x).strip()]
            if not prov_list:
                prov_list = ["mock"]
        else:
            prov_list = ["mock"]
        return cls(
            domain=data.get("domain", ""),
            tool_paths=tool_paths,
            discovery=DiscoveryConfig(
                enabled=d.get("enabled", True),
                expand_subdomains=d.get("expand_subdomains", True),
                providers=prov_list,
                timeout_seconds=int(d.get("timeout_seconds", 300)),
                wordlist=str(d.get("wordlist", "") or ""),
                resolvers=str(d.get("resolvers", "") or ""),
            ),
            scanning=ScanningConfig(
                enabled=s.get("enabled", True),
                parallel_workers=int(s.get("parallel_workers", 4)),
                rate_limit_per_second=float(s.get("rate_limit_per_second", 5)),
                plugins=list(s.get("plugins", ["mock_scanner"])),
                skip_duplicate_targets=s.get("skip_duplicate_targets", True),
                timeout_seconds=int(s.get("timeout_seconds", 300)),
                ffuf_wordlist=str(s.get("ffuf_wordlist", "") or ""),
                secretfinder_script=str(s.get("secretfinder_script", "") or ""),
                wafw00f_aggressive=bool(s.get("wafw00f_aggressive", False)),
            ),
            alerts=AlertsConfig(
                webhook_url=a.get("webhook_url", "") or "",
                min_severity=a.get("min_severity", "high"),
                batch_summaries=a.get("batch_summaries", True),
                deduplicate=a.get("deduplicate", True),
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
    data: dict[str, Any] = {}
    if path and path.is_file():
        data = _load_config_file(path)
    data = _deep_merge(data, _env_overrides())
    if cli_overrides:
        data = _deep_merge(data, cli_overrides)
    return AppConfig.from_dict(data)
