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
- [Methodology alignment (bug bounty recon)](#methodology-alignment-bug-bounty-recon)
- [The Bug Hunter’s Methodology (TBHM)](#the-bug-hunters-methodology-tbhm)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Composable discovery**: multiple sources merged and deduplicated (subdomains, CT logs, Wayback-derived hosts, etc.).
- **Analysis layer**: priority and tagging (API, auth, web, apex, **`non_www`** subdomain heuristic, **`port_scan_candidate`** on IPs) before scanning.
- **Plugin-based scanners**: standard contract (`run` → `parse` → `normalize`) with optional async execution.
- **Concurrency**: sequential, parallel (thread pool), or async scanning with shared rate limiting.
- **Duplicate scan suppression**: fingerprints persisted under the storage output directory.
- **JSON storage** with an abstract backend for future databases.
- **Webhook alerts**: severity thresholds, batching, in-run deduplication.
- **Debian-oriented bootstrap**: optional auto-install via `go install`, `pip`, and `apt-get` (see [External tools and bootstrap](#external-tools-and-bootstrap)).
- **Preflight tool checks**: logs `[OK]` / `[MISSING]` before installs; `--check-tools` for CI-style validation.
- **Real defaults without a config file**: discovery uses **all built-in sources** (crt.sh, subfinder, waybackurls, assetfinder, amass passive, GitHub subdomains, shuffledns, massdns stub); **URL collection** runs **gau**, **waybackurls**, **katana**, and **hakrawler**; scanning runs **every registered scanner** including **naabu**, **nmap**, **subjack**, **subzy**, **ffuf** (bundled `recon/data/ffuf-quick.txt`), **vhost ffuf**, **whatweb**, **wappalyzer**, and **secretfinder** (no-op until `scanning.secretfinder_script` is set). **`live_hosts_only` defaults to `false`** so non-httpx scanners see **all** assets; set `true` to gate on httpx-live hosts only. **`waf_skip_aggressive` defaults to `false`** so aggressive plugins still run when a WAF is detected (set `true` to skip them). See `recon/core/defaults.py`.
- **Methodology visibility**: [`recon/docs/METHODOLOGY.md`](recon/docs/METHODOLOGY.md) maps checklist-style recon playbooks to the pipeline; [**TBHM** (Jason Haddix)](recon/docs/TBHM.md) aligns with [jhaddix/tbhm](https://github.com/jhaddix/tbhm) (Discovery, mapping, port-scan themes). Image-only PDFs of the same methodology are noted there. Extra CLIs install via `--install-tools`.

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
# Real discovery + real scanners by default (needs network, Go/pip tools, or bootstrap auto_install)
cd AutoRecon-Framework
export PYTHONPATH=.
python3 recon/main.py --domain example.com --scan full

# Optional: YAML/JSON only to override workers, webhooks, wordlists, or swap providers
python3 recon/main.py --config recon/config/recon.example.json --domain target.example --scan quick
```

For **offline tests** only, use a small config that sets `discovery.providers` to `["mock"]` and `scanning.plugins` to `["mock_scanner"]`.

---

## Command-line interface

All flags are defined in `recon/main.py`.

| Option | Description |
|--------|-------------|
| `-d`, `--domain` | Target domain (overrides config `domain`) |
| `-c`, `--config` | Optional YAML/JSON overrides (defaults are already real discovery + scanners) |
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

**You do not need a config file** for a normal run: built-in defaults live in `recon/core/defaults.py` (full discovery list, full scanner list, collection on, JS analysis on).

Configuration is merged in this order (later wins):

1. **Built-in defaults** (from `defaults.py` / `AppConfig` dataclasses)  
2. Optional **file** (`--config`): YAML (needs PyYAML) or JSON  
3. **Environment** variables (`RECON_*`)  
4. **CLI** overrides (`--domain`, `--execution`)

Top-level and nested keys match the dataclasses in `recon/core/config_loader.py`. Example overrides (not required) live in:

- `recon/config/recon.example.yaml`
- `recon/config/recon.example.json`

### Common sections

| Section | Purpose |
|---------|---------|
| `domain` | Default target when `--domain` is omitted |
| `bootstrap` | `auto_install`: if `true`, missing CLIs required by enabled plugins/providers are installed after a preflight check |
| `tools` | Map logical names to binaries (absolute path or name on `PATH`) |
| `discovery` | `enabled`, `expand_subdomains`, `providers`, `timeout_seconds`, `wordlist`, `resolvers` |
| `scanning` | `enabled`, `plugins`, `parallel_workers`, `rate_limit_per_second`, `timeout_seconds`, `skip_duplicate_targets`, **`live_hosts_only`** (default `true`), `ffuf_wordlist`, **`vhost_ffuf_*`**, **`naabu_top_ports`**, **`nmap_top_ports`**, **`nmap_scripts`**, **`nmap_scan_timeout_seconds`**, `secretfinder_script`, `wafw00f_aggressive` |
| `alerts` | `webhook_url`, `min_severity`, `batch_summaries`, `deduplicate` |
| `execution` | `mode` (`sequential` \| `async`), `max_retries`, `retry_backoff_seconds` |
| `storage` | `output_dir` (relative to **current working directory** unless absolute), `backend` (reserved; JSON implemented) |
| `log_level`, `log_json` | Logging behavior |
| `stream_subprocess_output` | Default `true`: external tools’ **stdout/stderr** are echoed to the console (with `[tool:stdout]` / `[tool:stderr]` prefixes) while output is still captured for parsers. Set `false` for quieter logs. |

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
| `GITHUB_TOKEN` | (not mapped into config) | Required by **`github_subdomains`** discovery when not using a `.tokens` file; standard GitHub PAT for [github-subdomains](https://github.com/gwen001/github-subdomains) |

---

## Pipeline

1. **Load config** (file + env + CLI).  
2. **Bootstrap** (optional): prepend `~/.local/bin` and `$(go env GOPATH)/bin` to `PATH`; preflight log; install missing tools.  
3. **Discovery**: collect `Asset` records (hosts, metadata, source).  
4. **Analysis**: deduplicate, assign priority and tags.  
5. **Scanning**: for each asset (subject to rate limits and duplicate fingerprints), run → parse → normalize → `Finding` list. By default **`live_hosts_only`** is **`false`**, so **naabu**, **nmap**, **nuclei**, and other plugins run on **every** discovered asset (still subject to rate limits). Set **`live_hosts_only`: `true`** to run **httpx on all assets first** and restrict other plugins to **httpx-live** hosts only.  
6. **Storage**: write JSON under `storage.output_dir`.  
7. **Alerts**: POST webhook for findings at or above `min_severity` (if URL set).

Retries apply per stage in the engine (`execution.max_retries`).

---

## Discovery providers

Configured under `discovery.providers` (list). **If omitted**, defaults are the full list in `recon/core/defaults.py` (**crtsh**, **subfinder**, **waybackurls**, **assetfinder**, **amass_passive**, **github_subdomains**, **shuffledns**, **massdns**). **shuffledns** only emits hosts when **`discovery.wordlist`** and **`discovery.resolvers`** are set. Multiple entries are merged by `CompositeDiscoveryProvider` and deduplicated; the apex domain is injected if missing.

| Provider name | External dependency | Notes |
|-----------------|---------------------|--------|
| `mock` | None | Deterministic sample hosts (default) |
| `subfinder` | `subfinder` | Subdomain enumeration |
| `assetfinder` | `assetfinder` | Related hosts |
| `amass`, `amass_passive` | `amass` | Passive enum in adapter |
| `crtsh`, `crt.sh`, `crt_sh` | None | Certificate Transparency (HTTPS API) |
| `waybackurls`, `wayback` | `waybackurls` | Historical URLs → hostnames under scope |
| `shuffledns`, `shuffle_dns` | `shuffledns` | Requires `discovery.wordlist` and `discovery.resolvers` |
| `github_subdomains`, `github-subdomains` | `github-subdomains` | GitHub code search for hostnames ([gwen001/github-subdomains](https://github.com/gwen001/github-subdomains)); set **`GITHUB_TOKEN`** or a `.tokens` file per upstream docs |
| `massdns` | — | Stub (no automatic install) |

---

## Scanner plugins

Configured under `scanning.plugins` (list). **If omitted**, defaults are **all** built-in scanners in `recon/core/defaults.py` (including **naabu**, **nmap**, **ffuf** with bundled `recon/data/ffuf-quick.txt`, **vhost_ffuf**, **subjack**, **subzy**, **whatweb**, **wappalyzer**, **secretfinder**). Registered in `recon/plugins/registry.py`.

| Plugin | Dependency | Notes |
|--------|------------|--------|
| `mock_scanner` | None | Synthetic findings for pipeline tests |
| `httpx_scanner` | [ProjectDiscovery `httpx`](https://github.com/projectdiscovery/httpx) (Go) | HTTP(S) probe via stdin + `-json`; not Encode/python `httpx` |
| `nuclei_scanner` | `nuclei` | JSONL output per URL |
| `naabu_scanner` | `naabu` | **TCP port discovery** on each (live) host: `-host`, `-top-ports` ← `scanning.naabu_top_ports`, `-json`. Emits `open_tcp_port` findings. **Authorized scans only.** |
| `nmap_scanner` | `nmap` | **Service/version** (`-Pn -sV --top-ports` ← `scanning.nmap_top_ports`, `-oG -`). Optional `scanning.nmap_scripts` → `--script=…` for NSE (e.g. vuln checks where allowed). Emits `exposed_service` for CVE/template follow-up. Timeout: `nmap_scan_timeout_seconds`. |
| `wafw00f_scanner` | `wafw00f` | WAF detection; optional `scanning.wafw00f_aggressive` |
| `subjack_scanner` | `subjack` | Subdomain takeover checks |
| `subzy_scanner` | `subzy` | Subdomain takeover checks |
| `ffuf_scanner` | `ffuf` | Path fuzz: requires `scanning.ffuf_wordlist` |
| `vhost_ffuf_scanner` | `ffuf` | **Apex only:** one run per pipeline against the **root domain** (`--domain`), not each subdomain. [Vhost discovery](https://github.com/ffuf/ffuf#virtual-host-discovery-without-dns-records): `https://<IP>/` + `Host: FUZZ`. Default wordlist `recon/data/wl-vhost.txt` ([Avileox gist](https://gist.github.com/Avileox/941f5eb742bad690d04c16b78ac41b57)); `%s` → apex. Optional `vhost_ffuf_filter_size` / `vhost_ffuf_autocalibrate`. With `live_hosts_only`, other scanners still use live subdomains; vhost always targets the apex asset. |
| `secretfinder_scanner` | Python + script | Set `scanning.secretfinder_script` |

Exact CLI flags live in `recon/plugins/tool_scanners.py` and may need tuning for your tool versions.

**`scanning.live_hosts_only`** (default **`false`**): **every plugin × every asset** (unless duplicate fingerprints skip work). Set to **`true`** to reduce noise: the engine runs **httpx** on all assets first (from your plugin list or **implicitly** if you omitted `httpx_scanner` but listed other web scanners), then **naabu**, **nmap**, **nuclei**, etc. only on **httpx-live** hosts (≥1 JSON line). If httpx cannot be loaded from the registry, a warning is logged and non-httpx scanners fall back to all assets.

### Official CLI references

| Tool | Documentation |
|------|----------------|
| ProjectDiscovery httpx | [Running](https://docs.projectdiscovery.io/tools/httpx/running), [GitHub](https://github.com/projectdiscovery/httpx) |
| Nuclei | [Running](https://docs.projectdiscovery.io/tools/nuclei/running), [input formats](https://docs.projectdiscovery.io/opensource/nuclei/input-formats) |
| Subfinder | [ProjectDiscovery docs](https://docs.projectdiscovery.io/tools/subfinder/running) |
| wafw00f | [EnableSecurity/wafw00f](https://github.com/EnableSecurity/wafw00f) |
| FFUF | [ffuf project](https://github.com/ffuf/ffuf) — [Virtual host discovery](https://github.com/ffuf/ffuf#virtual-host-discovery-without-dns-records) (`-H "Host: FUZZ"`, `-fs` / `-ac`) |
| GAU | [lc/gau](https://github.com/lc/gau) |
| Katana | [projectdiscovery/katana](https://github.com/projectdiscovery/katana) |
| GoSpider | [jaeles-project/gospider](https://github.com/jaeles-project/gospider) |
| dnsx | [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) |
| Amass | [OWASP Amass](https://github.com/owasp-amass/amass) |
| naabu | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) (port scan; use on **authorized** targets only) |
| TBHM (methodology text) | [jhaddix/tbhm](https://github.com/jhaddix/tbhm) |

See [`recon/docs/METHODOLOGY.md`](recon/docs/METHODOLOGY.md) and [`recon/docs/TBHM.md`](recon/docs/TBHM.md) for OSINT and manual-only items (Shodan, Burp, Semgrep usage pattern, Clear-Sky-style workflows, etc.).

---

## External tools and bootstrap

Supported install recipes are declared in `recon/bootstrap/definitions.py` (core pipeline tools plus [methodology extras](recon/docs/METHODOLOGY.md)).

| Method | When |
|--------|------|
| **`go install …@latest`** | Most recon/scanner binaries |
| **`python -m pip install`** | e.g. `wafw00f` |
| **`apt-get install`** | Debian/Ubuntu family only (detected via `/etc/os-release`); e.g. `nmap`, **`libpcap-dev`** (build dep for **naabu**). Requires **root** or **passwordless `sudo -n`** for non-interactive installs |

Behavior:

- **Order**: when a tool lists **`apt_packages`**, those run **before** `pip` / `go install` so compile dependencies (e.g. naabu + libpcap) resolve on Debian.
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
    ├── docs/
    │   ├── METHODOLOGY.md      # Checklist-style recon crosswalk
    │   └── TBHM.md             # Jason Haddix TBHM ↔ pipeline (jhaddix/tbhm)
    ├── data/                   # Bundled wordlists (e.g. wl-vhost.txt)
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

## Methodology alignment (bug bounty recon)

The framework is designed to sit in a larger recon practice (apex discovery → subdomains → live hosts → scanning → manual testing). For a **full crosswalk** between:

- [R-s0n — DEF CON 32 Bug Bounty Village *recon-methodology.md*](https://github.com/R-s0n/bug-bounty-village-defcon32-workshop/blob/main/recon-methodology.md)
- [Infosec Writeups — *Recon to Master: The Complete Bug Bounty Checklist*](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0)

and **this repo** (what runs in the pipeline vs what `--install-tools` adds vs what stays manual/OSINT), see:

**[`recon/docs/METHODOLOGY.md`](recon/docs/METHODOLOGY.md)**

`--install-tools` installs **core** tools (subfinder, httpx, nuclei, etc.) plus **methodology-aligned extras** declared in `recon/bootstrap/definitions.py` (e.g. **github-subdomains**, **naabu**, **gau**, **katana**, **gospider**, **httprobe**, **dnsx**, **arjun**, **sublist3r**, **semgrep**, **cewl** on Debian). Extras other than enabled discovery providers do not run automatically until you add them to `discovery.providers` / `scanning.plugins` or call them from scripts.

---

## The Bug Hunter’s Methodology (TBHM)

Jason Haddix’s **The Bug Hunter’s Methodology** is maintained at **[github.com/jhaddix/tbhm](https://github.com/jhaddix/tbhm)**. This repo includes **[`recon/docs/TBHM.md`](recon/docs/TBHM.md)**, which maps TBHM themes (Discovery, port scanning, mapping, takeover checks, wide scanning) to AutoRecon providers, scanners, and bootstrap binaries.

**Note:** “TBHM Live” PDF one-pagers are often **image-based**; if text extraction is empty, use the GitHub repo and `TBHM.md` as the source of truth.

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
| **`httpx`: `No such option: -u` / `Usage: httpx [OPTIONS] URL`** | Wrong binary: often **Encode/python `httpx`** (`pip install httpx`) shadows [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx). Run `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` and set `tools.httpx` to `$(go env GOPATH)/bin/httpx`, or use `--install-tools`. The scanner feeds the URL on **stdin** and expects PD JSON lines. |

---

