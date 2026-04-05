"""
Built-in defaults: full pipeline (all discovery sources, collection, scanners).
Override via YAML/JSON --config or env. Use mock_* only for offline tests.
"""

from pathlib import Path

_RECON_PKG_ROOT = Path(__file__).resolve().parent.parent
"""`recon/` package directory (contains `data/`)."""

DEFAULT_FFUF_WORDLIST: str = str(_RECON_PKG_ROOT / "data" / "ffuf-quick.txt")
"""Bundled starter paths so ffuf_scanner always has a wordlist path."""

DEFAULT_DISCOVERY_PROVIDERS: list[str] = [
    "crtsh",
    "subfinder",
    "waybackurls",
    "assetfinder",
    "github_subdomains",
    "shuffledns",
    "massdns",
]

DEFAULT_SCANNING_PLUGINS: list[str] = [
    "httpx_scanner",
    "wafw00f_scanner",
    "nuclei_scanner",
    "whatweb_scanner",
    "wappalyzer_scanner",
    "naabu_scanner",
    "nmap_scanner",
    "subjack_scanner",
    "subzy_scanner",
    "ffuf_scanner",
    "vhost_ffuf_scanner",
    "secretfinder_scanner",
]

DEFAULT_COLLECTION_PROVIDERS: list[str] = [
    "gau",
    "waybackurls",
    "katana",
    "hakrawler",
]
