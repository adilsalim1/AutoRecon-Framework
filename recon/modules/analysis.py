from __future__ import annotations

from collections import defaultdict

from recon.models.assets import Asset, AssetType, Priority
from recon.utils.hostscope import hostname_in_scope, normalize_discovery_hostname


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
            if not self._identifier_plausible(a):
                continue
            key = a.identifier.lower().rstrip(".")
            if key in self._seen:
                continue
            self._seen.add(key)
            out.append(a)
        return out

    def _identifier_plausible(self, a: Asset) -> bool:
        """Drop path-like or out-of-scope hostnames from noisy discovery (e.g. amass)."""
        if a.asset_type == AssetType.JAVASCRIPT:
            return True
        ident = (a.identifier or "").strip()
        if ident.lower().startswith("http://") or ident.lower().startswith("https://"):
            return True
        parent = (a.parent_domain or "").strip().lower().rstrip(".")
        if not parent:
            return True
        h = normalize_discovery_hostname(ident)
        return bool(h and hostname_in_scope(h, parent))

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
        elif at == AssetType.SUBDOMAIN:
            # TBHM-style triage: non-www hosts are often less “flagship” (heuristic only).
            tags.add("surface")
            hid = asset.identifier.lower().strip().rstrip(".")
            if not hid.startswith("www."):
                tags.add("non_www")
            priority = Priority.MEDIUM
        elif at == AssetType.IP:
            tags.add("surface")
            tags.add("port_scan_candidate")
            priority = Priority.MEDIUM
        elif at == AssetType.JAVASCRIPT:
            tags.add("script")
            tags.add("secret_analysis_candidate")
            priority = Priority.HIGH

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
