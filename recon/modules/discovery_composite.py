from __future__ import annotations

from recon.core.logger import get_logger
from recon.models.assets import Asset, AssetType
from recon.modules.discovery import DiscoveryProvider

log = get_logger("discovery")


class CompositeDiscoveryProvider(DiscoveryProvider):
    """Run multiple discovery sources and merge (dedupe by identifier)."""

    def __init__(self, providers: list[DiscoveryProvider]) -> None:
        self._providers = providers

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        seen: set[str] = set()
        merged: list[Asset] = []
        base = domain.strip().lower().rstrip(".")

        for prov in self._providers:
            try:
                batch = prov.discover(domain, expand_subdomains=expand_subdomains)
            except Exception:
                log.exception("discovery provider %s failed", type(prov).__name__)
                continue
            for a in batch:
                key = a.identifier.lower().rstrip(".")
                if key in seen:
                    continue
                seen.add(key)
                merged.append(a)

        if base not in seen:
            merged.insert(
                0,
                Asset(
                    identifier=base,
                    asset_type=AssetType.DOMAIN,
                    parent_domain=base,
                    metadata={"source": "apex_injected"},
                ),
            )
        return merged
