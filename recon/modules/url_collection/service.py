from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from recon.core.logger import get_logger
from recon.models.assets import Asset, AssetType
from recon.modules.url_collection.collectors import (
    collect_gau,
    collect_hakrawler,
    collect_katana,
    collect_waybackurls,
)

log = get_logger("url_collection")


def _is_js_url(u: str) -> bool:
    low = u.lower().split("#")[0]
    path = low.split("?")[0]
    return path.endswith(".js") or ".js?" in low or "/static/js/" in path


def _has_query(u: str) -> bool:
    return "?" in u


def _api_like(u: str) -> bool:
    ul = u.lower()
    return any(
        p in ul
        for p in (
            "/api/",
            "/v1/",
            "/v2/",
            "/v3/",
            "/graphql",
            "/rest/",
            "/swagger",
            "api.",
        )
    )


def _endpoint_path(u: str) -> str | None:
    try:
        p = urlparse(u)
        if p.path and p.path != "/":
            return p.path
    except ValueError:
        return None
    return None


@dataclass
class UrlCollectionResult:
    urls: list[str] = field(default_factory=list)
    js_urls: list[str] = field(default_factory=list)
    urls_with_query: list[str] = field(default_factory=list)
    api_like_urls: list[str] = field(default_factory=list)
    endpoint_paths: list[str] = field(default_factory=list)
    providers_used: list[str] = field(default_factory=list)
    javascript_assets: list[Asset] = field(default_factory=list)

    def to_serializable(self) -> dict:
        return {
            "urls_count": len(self.urls),
            "js_urls_count": len(self.js_urls),
            "urls_with_query_count": len(self.urls_with_query),
            "api_like_count": len(self.api_like_urls),
            "endpoint_paths_sample": self.endpoint_paths[:200],
            "providers_used": list(self.providers_used),
            "javascript_assets": [a.to_dict() for a in self.javascript_assets],
        }


class UrlCollectionService:
    """Orchestrate passive + light active URL harvesters; categorize and build JS assets."""

    def __init__(
        self,
        *,
        providers: list[str],
        timeout_seconds: int,
        max_urls_per_host: int,
        max_crawl_seeds: int,
        stream_subprocess_output: bool,
    ) -> None:
        self._providers = [p.strip().lower() for p in providers if p.strip()]
        self._timeout = max(30, timeout_seconds)
        self._max_urls = max(10, max_urls_per_host)
        self._max_seeds = max(1, max_crawl_seeds)
        self._stream = stream_subprocess_output
        self._cap_total = min(50_000, max(500, max_urls_per_host * 25))

    def collect(
        self,
        domain: str,
        assets: list[Asset],
        tool_paths: dict[str, str],
    ) -> UrlCollectionResult:
        dom = domain.strip().lower().rstrip(".")
        raw_lines: list[str] = []
        used: list[str] = []

        for prov in self._providers:
            if prov in ("gau",):
                batch = collect_gau(dom, tool_paths, self._timeout, self._stream)
                raw_lines.extend(batch)
                used.append("gau")
            elif prov in ("waybackurls", "wayback"):
                batch = collect_waybackurls(dom, tool_paths, self._timeout, self._stream)
                raw_lines.extend(batch)
                used.append("waybackurls")
            elif prov in ("katana",):
                seeds = self._seeds_from_assets(dom, assets)
                for seed in seeds[: self._max_seeds]:
                    raw_lines.extend(
                        collect_katana(seed, tool_paths, self._timeout, self._stream)
                    )
                used.append("katana")
            elif prov in ("hakrawler",):
                seeds = self._seeds_from_assets(dom, assets)
                for seed in seeds[: self._max_seeds]:
                    raw_lines.extend(
                        collect_hakrawler(seed, tool_paths, self._timeout, self._stream)
                    )
                used.append("hakrawler")
            else:
                log.debug("unknown collection provider %r skipped", prov)

        seen: set[str] = set()
        urls: list[str] = []
        for line in raw_lines:
            u = line.strip()
            if not u.startswith("http"):
                continue
            if u in seen:
                continue
            seen.add(u)
            urls.append(u)
            if len(urls) >= self._cap_total:
                break

        js_urls: list[str] = []
        q_urls: list[str] = []
        api_urls: list[str] = []
        paths: set[str] = set()
        for u in urls:
            if _is_js_url(u):
                js_urls.append(u)
            if _has_query(u):
                q_urls.append(u)
            if _api_like(u):
                api_urls.append(u)
            ep = _endpoint_path(u)
            if ep:
                paths.add(ep)

        js_assets: list[Asset] = []
        seen_js: set[str] = set()
        for ju in js_urls:
            if ju in seen_js:
                continue
            seen_js.add(ju)
            js_assets.append(
                Asset(
                    identifier=ju,
                    asset_type=AssetType.JAVASCRIPT,
                    parent_domain=dom,
                    metadata={"source": "url_collection", "kind": "javascript"},
                )
            )

        log.info(
            "url collection: %s unique URLs (%s JS) providers=%s",
            len(urls),
            len(js_urls),
            used,
        )
        return UrlCollectionResult(
            urls=urls,
            js_urls=js_urls,
            urls_with_query=q_urls,
            api_like_urls=api_urls,
            endpoint_paths=sorted(paths)[:5000],
            providers_used=used,
            javascript_assets=js_assets,
        )

    def _seeds_from_assets(self, dom: str, assets: list[Asset]) -> list[str]:
        seeds: list[str] = []
        for a in assets:
            hid = a.identifier.strip().lower().rstrip(".")
            if not hid or hid == dom:
                continue
            if "://" in hid:
                seeds.append(hid)
                continue
            seeds.append(f"https://{hid}/")
        if f"https://{dom}/" not in seeds:
            seeds.insert(0, f"https://{dom}/")
        return seeds
