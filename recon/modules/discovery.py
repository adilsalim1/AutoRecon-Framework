from __future__ import annotations

from abc import ABC, abstractmethod

from recon.models.assets import Asset, AssetType


class DiscoveryProvider(ABC):
    """Tool-agnostic discovery: domain expansion, asset collection."""

    @abstractmethod
    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        """Return structured assets for downstream analysis."""
        ...


class MockDiscoveryProvider(DiscoveryProvider):
    """
    Placeholder discovery producing deterministic sample assets.
    Swap for DNS enumeration, certificate transparency, cloud inventory, etc.
    """

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        base = domain.strip().lower().rstrip(".")
        assets: list[Asset] = [
            Asset(
                identifier=base,
                asset_type=AssetType.DOMAIN,
                parent_domain=base,
                metadata={"source": "mock_discovery"},
            )
        ]
        if expand_subdomains:
            for sub in ("www", "api", "auth", "staging", "cdn"):
                host = f"{sub}.{base}"
                at = AssetType.API if sub == "api" else AssetType.AUTH if sub == "auth" else AssetType.WEB
                assets.append(
                    Asset(
                        identifier=host,
                        asset_type=at,
                        parent_domain=base,
                        metadata={"source": "mock_discovery", "subdomain": sub},
                    )
                )
        return assets
