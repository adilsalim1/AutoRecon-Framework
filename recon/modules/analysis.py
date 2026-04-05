from __future__ import annotations

from collections import defaultdict

from recon.models.assets import Asset, AssetType, Priority


class AssetAnalyzer:
    """Deduplicate, normalize, prioritize, and tag assets for scanning."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def analyze(self, assets: list[Asset]) -> list[Asset]:
        deduped = self._dedupe(assets)
        return [self._classify(a) for a in deduped]

    def _dedupe(self, assets: list[Asset]) -> list[Asset]:
        out: list[Asset] = []
        for a in assets:
            key = a.identifier.lower().rstrip(".")
            if key in self._seen:
                continue
            self._seen.add(key)
            out.append(a)
        return out

    def _classify(self, asset: Asset) -> Asset:
        tags = set(asset.tags)
        priority = asset.priority
        at = asset.asset_type

        if at == AssetType.API:
            tags.add("high_value")
            priority = Priority.HIGH
        elif at == AssetType.AUTH:
            tags.add("high_value")
            tags.add("identity")
            priority = Priority.CRITICAL
        elif at == AssetType.DOMAIN:
            tags.add("apex")
            priority = Priority.MEDIUM
        elif at == AssetType.WEB:
            tags.add("surface")
            priority = Priority.HIGH if "www" in asset.identifier else Priority.MEDIUM

        meta = dict(asset.metadata)
        meta.setdefault("analyzed", True)

        return Asset(
            identifier=asset.identifier,
            asset_type=at,
            priority=priority,
            tags=frozenset(tags),
            metadata=meta,
            discovered_at=asset.discovered_at,
            parent_domain=asset.parent_domain,
        )

    @staticmethod
    def summarize_by_priority(assets: list[Asset]) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for a in assets:
            counts[a.priority.value] += 1
        return dict(counts)
