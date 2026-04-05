from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    """How to satisfy a logical tool dependency."""

    key: str
    """Key used in config `tools:` map and tool_paths."""
    check_names: tuple[str, ...]
    """CLI names tried with shutil.which (first hit wins)."""
    go_package: str | None = None
    """Full `go install <pkg>` module path (includes @version)."""
    pip_package: str | None = None
    """Optional pip requirement string."""
    apt_packages: tuple[str, ...] = ()
    """Debian/Ubuntu packages installed via apt-get when running as root or passwordless sudo."""


# Supported third-party binaries (Go / pip / apt on Debian family). Paths may change upstream.
TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        key="subfinder",
        check_names=("subfinder",),
        go_package="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    ToolSpec(
        key="httpx",
        check_names=("httpx",),
        go_package="github.com/projectdiscovery/httpx/cmd/httpx@latest",
    ),
    ToolSpec(
        key="nuclei",
        check_names=("nuclei",),
        go_package="github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
    ),
    ToolSpec(
        key="ffuf",
        check_names=("ffuf",),
        go_package="github.com/ffuf/ffuf/v2@latest",
    ),
    ToolSpec(
        key="assetfinder",
        check_names=("assetfinder",),
        go_package="github.com/tomnomnom/assetfinder@latest",
    ),
    ToolSpec(
        key="waybackurls",
        check_names=("waybackurls",),
        go_package="github.com/tomnomnom/waybackurls@latest",
    ),
    ToolSpec(
        key="shuffledns",
        check_names=("shuffledns",),
        go_package="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
    ),
    ToolSpec(
        key="amass",
        check_names=("amass",),
        go_package="github.com/OWASP/Amass/v4/cmd/amass@latest",
    ),
    ToolSpec(
        key="github_subdomains",
        check_names=("github-subdomains",),
        go_package="github.com/gwen001/github-subdomains@latest",
    ),
    ToolSpec(
        key="subjack",
        check_names=("subjack",),
        go_package="github.com/haccer/subjack@latest",
    ),
    ToolSpec(
        key="subzy",
        check_names=("subzy",),
        go_package="github.com/PentestPad/subzy/v2/cmd/subzy@latest",
    ),
    ToolSpec(
        key="wafw00f",
        check_names=("wafw00f",),
        pip_package="wafw00f>=2.2.0",
    ),
    ToolSpec(
        key="nmap",
        check_names=("nmap",),
        apt_packages=("nmap",),
    ),
    ToolSpec(
        key="naabu",
        check_names=("naabu",),
        apt_packages=("libpcap-dev",),
        go_package="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    ),
    # --- Methodology-aligned extras (R-s0n recon + bug-bounty checklists): install via
    # `python recon/main.py --install-tools` — not all have pipeline plugins yet; see recon/docs/METHODOLOGY.md
    ToolSpec(
        key="gau",
        check_names=("gau",),
        go_package="github.com/lc/gau/v2/cmd/gau@latest",
    ),
    ToolSpec(
        key="katana",
        check_names=("katana",),
        go_package="github.com/projectdiscovery/katana/cmd/katana@latest",
    ),
    ToolSpec(
        key="hakrawler",
        check_names=("hakrawler",),
        go_package="github.com/hakluke/hakrawler@latest",
    ),
    ToolSpec(
        key="whatweb",
        check_names=("whatweb",),
        apt_packages=("whatweb",),
    ),
    ToolSpec(
        key="wappalyzer",
        check_names=("wappalyzer",),
    ),
    ToolSpec(
        key="gospider",
        check_names=("gospider",),
        go_package="github.com/jaeles-project/gospider@latest",
    ),
    ToolSpec(
        key="httprobe",
        check_names=("httprobe",),
        go_package="github.com/tomnomnom/httprobe@latest",
    ),
    ToolSpec(
        key="dnsx",
        check_names=("dnsx",),
        go_package="github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    ),
    ToolSpec(
        key="arjun",
        check_names=("arjun",),
        pip_package="arjun>=2.2.1",
    ),
    ToolSpec(
        key="sublist3r",
        check_names=("sublist3r",),
        pip_package="Sublist3r>=1.0",
    ),
    ToolSpec(
        key="semgrep",
        check_names=("semgrep",),
        pip_package="semgrep>=1.40.0",
    ),
    ToolSpec(
        key="cewl",
        check_names=("cewl",),
        apt_packages=("cewl",),
    ),
)

_BY_KEY: dict[str, ToolSpec] = {s.key: s for s in TOOL_SPECS}

DISCOVERY_PROVIDER_TOOLS: dict[str, frozenset[str]] = {
    "mock": frozenset(),
    "mock_discovery": frozenset(),
    "subfinder": frozenset({"subfinder"}),
    "assetfinder": frozenset({"assetfinder"}),
    "amass": frozenset({"amass"}),
    "amass_passive": frozenset({"amass"}),
    "crtsh": frozenset(),
    "crt.sh": frozenset(),
    "crt_sh": frozenset(),
    "waybackurls": frozenset({"waybackurls"}),
    "wayback": frozenset({"waybackurls"}),
    "github_subdomains": frozenset({"github_subdomains"}),
    "github-subdomains": frozenset({"github_subdomains"}),
    "githubsubdomains": frozenset({"github_subdomains"}),
    "shuffledns": frozenset({"shuffledns"}),
    "shuffle_dns": frozenset({"shuffledns"}),
    "massdns": frozenset(),
}

COLLECTION_PROVIDER_TOOLS: dict[str, frozenset[str]] = {
    "gau": frozenset({"gau"}),
    "waybackurls": frozenset({"waybackurls"}),
    "wayback": frozenset({"waybackurls"}),
    "katana": frozenset({"katana"}),
    "hakrawler": frozenset({"hakrawler"}),
}


SCANNER_PLUGIN_TOOLS: dict[str, frozenset[str]] = {
    "mock_scanner": frozenset(),
    "httpx_scanner": frozenset({"httpx"}),
    "nuclei_scanner": frozenset({"nuclei"}),
    "subjack_scanner": frozenset({"subjack"}),
    "subzy_scanner": frozenset({"subzy"}),
    "ffuf_scanner": frozenset({"ffuf"}),
    "vhost_ffuf_scanner": frozenset({"ffuf"}),
    "wafw00f_scanner": frozenset({"wafw00f"}),
    "naabu_scanner": frozenset({"naabu"}),
    "nmap_scanner": frozenset({"nmap"}),
    "secretfinder_scanner": frozenset(),
    "whatweb_scanner": frozenset({"whatweb"}),
    "wappalyzer_scanner": frozenset({"wappalyzer"}),
}


def spec_for_key(key: str) -> ToolSpec | None:
    return _BY_KEY.get(key)


def required_tool_keys_for_config(
    discovery_providers: list[str],
    scanner_plugins: list[str],
    collection_providers: list[str] | None = None,
) -> frozenset[str]:
    keys: set[str] = set()
    for p in discovery_providers:
        keys |= set(DISCOVERY_PROVIDER_TOOLS.get(p.strip().lower(), frozenset()))
    for p in scanner_plugins:
        keys |= set(SCANNER_PLUGIN_TOOLS.get(p.strip().lower(), frozenset()))
    for p in collection_providers or []:
        keys |= set(COLLECTION_PROVIDER_TOOLS.get(p.strip().lower(), frozenset()))
    return frozenset(keys)
