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
    "shuffledns": frozenset({"shuffledns"}),
    "shuffle_dns": frozenset({"shuffledns"}),
    "massdns": frozenset(),
}

SCANNER_PLUGIN_TOOLS: dict[str, frozenset[str]] = {
    "mock_scanner": frozenset(),
    "httpx_scanner": frozenset({"httpx"}),
    "nuclei_scanner": frozenset({"nuclei"}),
    "subjack_scanner": frozenset({"subjack"}),
    "subzy_scanner": frozenset({"subzy"}),
    "ffuf_scanner": frozenset({"ffuf"}),
    "wafw00f_scanner": frozenset({"wafw00f"}),
    "secretfinder_scanner": frozenset(),
}


def spec_for_key(key: str) -> ToolSpec | None:
    return _BY_KEY.get(key)


def required_tool_keys_for_config(discovery_providers: list[str], scanner_plugins: list[str]) -> frozenset[str]:
    keys: set[str] = set()
    for p in discovery_providers:
        keys |= set(DISCOVERY_PROVIDER_TOOLS.get(p.strip().lower(), frozenset()))
    for p in scanner_plugins:
        keys |= set(SCANNER_PLUGIN_TOOLS.get(p.strip().lower(), frozenset()))
    return frozenset(keys)
