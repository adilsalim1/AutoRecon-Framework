"""
Built-in defaults: real discovery and real scanners (no config file required).
Override via YAML/JSON --config or env if needed. Use mock_* only for offline tests.
"""

DEFAULT_DISCOVERY_PROVIDERS: list[str] = ["crtsh", "subfinder", "waybackurls"]

DEFAULT_SCANNING_PLUGINS: list[str] = [
    "httpx_scanner",
    "wafw00f_scanner",
    "nuclei_scanner",
]
