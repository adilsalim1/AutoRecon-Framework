# AutoRecon Framework

Modular attack-surface reconnaissance and automated assessment pipeline for **Python 3.10+**. It orchestrates **discovery → analysis → scanning → storage → alerts** with a **tool-agnostic** plugin model: external binaries are invoked through thin adapters, not hard-wired into the core.

**Use only on systems and networks you are authorized to test.** Unauthorized scanning is illegal in most jurisdictions.

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command-line interface](#command-line-interface)
- [Configuration](#configuration)
- [Environment variables](#environment-variables)
- [Pipeline](#pipeline)
- [Discovery providers](#discovery-providers)
- [Scanner plugins](#scanner-plugins)
- [External tools and bootstrap](#external-tools-and-bootstrap)
- [Output artifacts](#output-artifacts)
- [Alerts (webhooks)](#alerts-webhooks)
- [Project layout](#project-layout)
- [Extending the framework](#extending-the-framework)

---

## Features

- **Composable discovery**: multiple sources merged and deduplicated (subdomains, CT logs, Wayback-derived hosts, etc.).
- **Analysis layer**: priority and tagging (API, auth, web, apex) before scanning.
- **Plugin-based scanners**: standard contract (`run` → `parse` → `normalize`) with optional async execution.
- **Concurrency**: sequential, parallel (thread pool), or async scanning with shared rate limiting.
- **Duplicate scan suppression**: fingerprints persisted under the storage output directory.
- **JSON storage** with an abstract backend for future databases.
- **Webhook alerts**: severity thresholds, batching, in-run deduplication.
- **Debian-oriented bootstrap**: optional auto-install via `go install`, `pip`, and `apt-get` (see [External tools and bootstrap](#external-tools-and-bootstrap)).
- **Preflight tool checks**: logs `[OK]` / `[MISSING]` before installs; `--check-tools` for CI-style validation.

---

## Requirements

| Component | Notes |
|-----------|--------|
| **Python** | 3.10 or newer |
| **PyYAML** | Required only if you use `.yaml` / `.yml` config files (`pip install -r requirements.txt`) |
| **Go** | Needed for ProjectDiscovery / ffuf / tomnomnom-style tools when using bootstrap installs |
| **Network** | Required when discovery or scanners call the internet, and when `bootstrap.auto_install` runs |

---

## Installation

```bash
cd AutoRecon-Framework
pip install -r requirements.txt
```

Run the CLI from the repository root with `PYTHONPATH` pointing at the project root (the parent of the `recon` package):

```bash
export PYTHONPATH=.
python recon/main.py --help
```

---

## Quick start

```bash
# Default config is in-memory (mock discovery + mock scanner); domain from CLI
PYTHONPATH=. python recon/main.py --domain example.com --scan quick

# Use a copied example config
cp recon/config/recon.example.yaml my-recon.yaml
# Edit domain, discovery.providers, scanning.plugins, etc.
PYTHONPATH=. python recon/main.py --config my-recon.yaml --domain target.example
```

---

## Command-line interface

All flags are defined in `recon/main.py`.

| Option | Description |
|--------|-------------|
| `-d`, `--domain` | Target domain (overrides config `domain`) |
| `-c`, `--config` | Path to YAML or JSON configuration file |
| `--scan` | One of `full`, `quick`, `none`: `full` uses parallel scanning when workers > 1; `quick` forces one worker and sequential mode; `none` skips scanning |
| `--execution` | `sequential` or `async`; overrides `execution.mode` in config |
| `--install-tools` | Install **all** supported external tools (then exit; status code 0/1) |
| `--check-tools` | Resolve required tools from config; print OK/NO lines; exit **0** if all present, **1** if any missing |
| `--no-auto-tools` | Disables `bootstrap.auto_install` for this run |

Examples:

```bash
PYTHONPATH=. python recon/main.py --install-tools
PYTHONPATH=. python recon/main.py --check-tools -c my-recon.yaml
PYTHONPATH=. python recon/main.py --no-auto-tools -d example.com --scan full
```

---

## Configuration

Configuration is merged in this order (later wins):

1. Optional **file** (`--config`): YAML (needs PyYAML) or JSON  
2. **Environment** variables (`RECON_*`)  
3. **CLI** overrides (`--domain`, `--execution`)

Top-level and nested keys match the dataclasses in `recon/core/config_loader.py`. A commented reference lives in:

- `recon/config/recon.example.yaml`
- `recon/config/recon.example.json`

### Common sections

| Section | Purpose |
|---------|---------|
| `domain` | Default target when `--domain` is omitted |
| `bootstrap` | `auto_install`: if `true`, missing CLIs required by enabled plugins/providers are installed after a preflight check |
| `tools` | Map logical names to binaries (absolute path or name on `PATH`) |
| `discovery` | `enabled`, `expand_subdomains`, `providers`, `timeout_seconds`, `wordlist`, `resolvers` |
| `scanning` | `enabled`, `plugins`, `parallel_workers`, `rate_limit_per_second`, `timeout_seconds`, `skip_duplicate_targets`, `ffuf_wordlist`, `secretfinder_script`, `wafw00f_aggressive` |
| `alerts` | `webhook_url`, `min_severity`, `batch_summaries`, `deduplicate` |
| `execution` | `mode` (`sequential` \| `async`), `max_retries`, `retry_backoff_seconds` |
| `storage` | `output_dir` (relative to **current working directory** unless absolute), `backend` (reserved; JSON implemented) |
| `log_level`, `log_json` | Logging behavior |

---

## Environment variables

| Variable | Config target |
|----------|----------------|
| `RECON_DOMAIN` | `domain` |
| `RECON_LOG_LEVEL` | `log_level` |
| `RECON_WEBHOOK_URL` | `alerts.webhook_url` |
| `RECON_ALERT_MIN_SEVERITY` | `alerts.min_severity` |
| `RECON_SCAN_RATE` | `scanning.rate_limit_per_second` |
| `RECON_SCAN_WORKERS` | `scanning.parallel_workers` |
| `RECON_EXECUTION_MODE` | `execution.mode` |
| `RECON_OUTPUT_DIR` | `storage.output_dir` |

---

## Pipeline

1. **Load config** (file + env + CLI).  
2. **Bootstrap** (optional): prepend `~/.local/bin` and `$(go env GOPATH)/bin` to `PATH`; preflight log; install missing tools.  
3. **Discovery**: collect `Asset` records (hosts, metadata, source).  
4. **Analysis**: deduplicate, assign priority and tags.  
5. **Scanning**: for each enabled scanner plugin and asset (subject to rate limits and duplicate fingerprints), run → parse → normalize → `Finding` list.  
6. **Storage**: write JSON under `storage.output_dir`.  
7. **Alerts**: POST webhook for findings at or above `min_severity` (if URL set).

Retries apply per stage in the engine (`execution.max_retries`).

---

## Discovery providers

Configured under `discovery.providers` (list). Multiple entries are merged by `CompositeDiscoveryProvider` and deduplicated; the apex domain is injected if missing.

| Provider name | External dependency | Notes |
|-----------------|---------------------|--------|
| `mock` | None | Deterministic sample hosts (default) |
| `subfinder` | `subfinder` | Subdomain enumeration |
| `assetfinder` | `assetfinder` | Related hosts |
| `amass`, `amass_passive` | `amass` | Passive enum in adapter |
| `crtsh`, `crt.sh`, `crt_sh` | None | Certificate Transparency (HTTPS API) |
| `waybackurls`, `wayback` | `waybackurls` | Historical URLs → hostnames under scope |
| `shuffledns`, `shuffle_dns` | `shuffledns` | Requires `discovery.wordlist` and `discovery.resolvers` |
| `massdns` | — | Stub (no automatic install) |

---

## Scanner plugins

Configured under `scanning.plugins` (list). Registered in `recon/plugins/registry.py`.

| Plugin | Dependency | Notes |
|--------|------------|--------|
| `mock_scanner` | None | Synthetic findings for pipeline tests |
| `httpx_scanner` | `httpx` | HTTP(S) probe; tech/title in evidence |
| `nuclei_scanner` | `nuclei` | JSONL output per URL |
| `wafw00f_scanner` | `wafw00f` | WAF detection; optional `scanning.wafw00f_aggressive` |
| `subjack_scanner` | `subjack` | Subdomain takeover checks |
| `subzy_scanner` | `subzy` | Subdomain takeover checks |
| `ffuf_scanner` | `ffuf` | Requires `scanning.ffuf_wordlist` path |
| `secretfinder_scanner` | Python + script | Set `scanning.secretfinder_script` |

Exact CLI flags live in `recon/plugins/tool_scanners.py` and may need tuning for your tool versions.

---

## External tools and bootstrap

Supported install recipes are declared in `recon/bootstrap/definitions.py`.

| Method | When |
|--------|------|
| **`go install …@latest`** | Most recon/scanner binaries |
| **`python -m pip install`** | e.g. `wafw00f` |
| **`apt-get install`** | Debian/Ubuntu family only (detected via `/etc/os-release`); e.g. `nmap`. Requires **root** or **passwordless `sudo -n`** for non-interactive installs |

Behavior:

- **Preflight**: before any install, each required tool is checked (`PATH` or `tools.<key>` path). Logs use `[OK]` / `[MISSING]`.
- **PATH**: `~/.local/bin` and `GOPATH/bin` are prepended for the current process so new installs are visible immediately.

Disable automatic installs for locked-down hosts:

```yaml
bootstrap:
  auto_install: false
```

or use `--no-auto-tools`.

**Not auto-managed**: SecretFinder script path, ShuffleDNS wordlists/resolvers, custom massdns workflows.

---

## Output artifacts

Written under `storage.output_dir` (default `output/` relative to the **current working directory**):

| File pattern | Content |
|--------------|---------|
| `assets_<run_id>.json` | Normalized assets after analysis |
| `findings_<run_id>.json` | Unified findings |
| `scans_<run_id>.jsonl` | One JSON object per scan record |
| `scan_fingerprints.json` | Persistent (asset + scanner) fingerprints to skip duplicate work |

---

## Alerts (webhooks)

If `alerts.webhook_url` is set, the notifier sends JSON **POST** requests (`Content-Type: application/json`):

- **Batch mode** (`batch_summaries: true`): one payload with multiple findings and severity counts.
- **Severity filter**: only findings at or above `min_severity` (`critical`, `high`, `medium`, `low`, `info`).
- **Dedup** (`deduplicate: true`): suppresses repeated `dedupe_key` values within the same process run.

---

## Project layout

```text
AutoRecon-Framework/
├── requirements.txt
├── README.md
└── recon/
    ├── main.py                 # CLI entry
    ├── __init__.py
    ├── config/                 # Example YAML/JSON
    ├── bootstrap/              # Tool specs + Debian-oriented installer
    ├── core/                   # Engine, config, logger, scheduler, discovery factory
    ├── modules/                # discovery, analysis, scanning, storage, notifier
    ├── plugins/                # Scanner plugins + registry
    ├── models/                 # Asset, Finding, enums
    ├── utils/                  # Rate limiting, subprocess helpers
    └── output/                 # Optional placeholder directory in repo
```

---

## Extending the framework

1. **New scanner**  
   - Subclass `ScannerPlugin` in `recon/plugins/base.py`.  
   - Implement `run`, `parse`, and optionally `normalize`.  
   - Register in `load_builtin_plugins()` in `recon/plugins/registry.py`.  
   - Add a `SCANNER_PLUGIN_TOOLS` mapping in `recon/bootstrap/definitions.py` if the plugin needs a bootstrap recipe.

2. **New discovery source**  
   - Implement `DiscoveryProvider` (`recon/modules/discovery.py`).  
   - Wire it in `recon/core/discovery_factory.py`.  
   - Add `DISCOVERY_PROVIDER_TOOLS` entries if it needs external binaries.

3. **New storage backend**  
   - Subclass `StorageBackend` in `recon/modules/storage.py` and inject it into `PipelineEngine`.

4. **Scheduled runs**  
   - Run the CLI from **cron** or **systemd timers** on Debian, or use `recon/core/scheduler.py` as a hook for long-lived workers.

---

## Troubleshooting

| Issue | What to check |
|-------|----------------|
| `ModuleNotFoundError: yaml` | Install PyYAML or use a `.json` config |
| Tool not found after `go install` | Ensure `$(go env GOPATH)/bin` is on `PATH` (the framework prepends it in-process) |
| **`go install failed: go not found`** | The Go toolchain is missing. On Debian/Kali the framework tries **`apt install golang-go`** automatically if it can run `apt-get` (root or passwordless `sudo`). Otherwise run: `sudo apt install golang-go` or install Go from [go.dev/dl](https://go.dev/dl/). |
| `apt-get` install skipped | Run as root (e.g. container) or configure passwordless `sudo -n` for `apt-get` |
| Empty findings | Duplicate fingerprints in `scan_fingerprints.json`, or scanners not in `scanning.plugins` |
| Wrong CLI behavior | Compare your tool version with arguments in `recon/plugins/tool_scanners.py` |

---

