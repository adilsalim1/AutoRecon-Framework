from __future__ import annotations

from recon.core.config_loader import AppConfig
from recon.core.logger import get_logger
from recon.modules.discovery import DiscoveryProvider, MockDiscoveryProvider
from recon.modules.discovery_composite import CompositeDiscoveryProvider
from recon.modules.discovery_external import (
    AmassPassiveDiscoveryProvider,
    AssetfinderDiscoveryProvider,
    CrtShDiscoveryProvider,
    MassDnsDiscoveryProvider,
    ShuffleDnsDiscoveryProvider,
    SubfinderDiscoveryProvider,
    WaybackurlsDiscoveryProvider,
)

log = get_logger("discovery_factory")


def build_discovery(config: AppConfig) -> DiscoveryProvider:
    names = [n.strip().lower() for n in (config.discovery.providers or [])]
    if not names:
        names = ["mock"]

    parts: list[DiscoveryProvider] = []
    for n in names:
        if n in ("mock", "mock_discovery"):
            parts.append(MockDiscoveryProvider())
        elif n == "subfinder":
            parts.append(
                SubfinderDiscoveryProvider(
                    config.tool_paths, timeout=config.discovery.timeout_seconds
                )
            )
        elif n in ("assetfinder",):
            parts.append(
                AssetfinderDiscoveryProvider(
                    config.tool_paths, timeout=config.discovery.timeout_seconds
                )
            )
        elif n in ("amass", "amass_passive"):
            parts.append(
                AmassPassiveDiscoveryProvider(
                    config.tool_paths, timeout=config.discovery.timeout_seconds
                )
            )
        elif n in ("crtsh", "crt.sh", "crt_sh"):
            parts.append(CrtShDiscoveryProvider(timeout=config.discovery.timeout_seconds))
        elif n in ("waybackurls", "wayback"):
            parts.append(
                WaybackurlsDiscoveryProvider(
                    config.tool_paths, timeout=config.discovery.timeout_seconds
                )
            )
        elif n in ("shuffledns", "shuffle_dns"):
            parts.append(
                ShuffleDnsDiscoveryProvider(
                    config.tool_paths,
                    wordlist=config.discovery.wordlist,
                    resolvers=config.discovery.resolvers,
                    timeout=max(config.discovery.timeout_seconds, 600),
                )
            )
        elif n in ("massdns",):
            parts.append(MassDnsDiscoveryProvider())
        else:
            log.warning("unknown discovery provider %r — skipping", n)

    if not parts:
        log.warning("no valid discovery providers; using mock")
        parts = [MockDiscoveryProvider()]

    return CompositeDiscoveryProvider(parts)
