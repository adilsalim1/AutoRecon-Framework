"""
Merge discovery assets + URL harvest into deduplicated surface lists (domains, URLs, paths).
"""

from __future__ import annotations

from urllib.parse import urlparse

from recon.models.assets import Asset
from recon.models.findings import Finding
from recon.modules.url_collection.service import UrlCollectionResult


def normalize_host(h: str) -> str:
    s = (h or "").strip().lower().rstrip(".")
    if "://" in s:
        try:
            p = urlparse(s)
            hn = p.hostname
            if hn:
                return hn.lower().rstrip(".")
        except ValueError:
            pass
    return s.split("/")[0].split(":")[0]


def host_from_url(url: str) -> str | None:
    try:
        p = urlparse(url.strip())
        hn = p.hostname
        if hn:
            return hn.lower().rstrip(".")
    except ValueError:
        pass
    return None


def _scope_match_roots(apex: str) -> tuple[str, ...]:
    """
    DNS roots for the configured scope: the apex plus, if it is a ``www.`` host,
    the bare registrable-style parent so sibling subdomains stay in scope.
    """
    a = normalize_host(apex)
    if not a:
        return ()
    roots: list[str] = [a]
    if a.startswith("www.") and len(a) > 4:
        bare = a[4:]
        if bare and bare not in roots:
            roots.append(bare)
    return tuple(roots)


def host_is_under_apex(host: str, apex: str) -> bool:
    """
    True if ``host`` is the configured scope or a subdomain of any scope root,
    excluding third-party hosts (``bit.ly``, ``apps.apple.com``) from URL harvest.
    """
    h = normalize_host(host)
    if not h:
        return False
    for a in _scope_match_roots(apex):
        if not a:
            continue
        if h == a or h.endswith("." + a):
            return True
    return False


def build_surface_inventory(
    domain: str,
    assets: list[Asset],
    collection: UrlCollectionResult | None,
) -> dict:
    """
    Produce sorted deduplicated lists: domains (hosts), absolute URLs, endpoint paths.
    Hosts implied by collected URLs are included in domains.
    """
    apex = normalize_host(domain)
    seen_hosts: set[str] = set()
    domains: list[str] = []

    def add_host(h: str) -> None:
        n = normalize_host(h)
        if not n or n in seen_hosts:
            return
        if not host_is_under_apex(n, apex):
            return
        seen_hosts.add(n)
        domains.append(n)

    for a in assets:
        add_host(a.identifier)

    seen_url: set[str] = set()
    urls: list[str] = []
    raw_urls = list(collection.urls) if collection else []
    for u in raw_urls:
        u = u.strip()
        if not u.startswith("http"):
            continue
        hh = host_from_url(u)
        if not hh or not host_is_under_apex(hh, apex):
            continue
        if u in seen_url:
            continue
        seen_url.add(u)
        urls.append(u)
        if hh:
            add_host(hh)

    seen_path: set[str] = set()
    endpoint_paths: list[str] = []
    # Paths only from in-scope URLs (skip paths implied by external redirect domains).
    for u in urls:
        try:
            p = urlparse(u)
            if p.path and p.path != "/" and p.path not in seen_path:
                seen_path.add(p.path)
                endpoint_paths.append(p.path)
        except ValueError:
            pass

    domains.sort()
    endpoint_paths.sort()
    return {
        "apex": apex,
        "domains": domains,
        "domains_count": len(domains),
        "urls": urls,
        "urls_count": len(urls),
        "endpoint_paths": endpoint_paths,
        "endpoints_count": len(endpoint_paths),
    }


def httpx_target_lines(
    inventory: dict,
    *,
    max_urls: int,
) -> list[str]:
    """
    One HTTPS root URL per discovered host only (``https://host/``).
    Does not probe each harvested path/URL — tech / live checks are domain-level.
    ``max_urls`` caps how many hosts are probed (0 = all hosts).
    """
    seen: set[str] = set()
    out: list[str] = []
    for d in inventory.get("domains") or []:
        if max_urls > 0 and len(out) >= max_urls:
            break
        u = f"https://{normalize_host(d)}/"
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extend_inventory_with_finding_hosts(inventory: dict, findings: list[Finding]) -> None:
    """Add hostnames inferred from enumeration findings (e.g. vhost, ffuf URLs)."""
    apex = str(inventory.get("apex") or "").strip()
    hosts = set(inventory.get("domains") or [])
    for f in findings:
        t = (f.target or "").strip()
        if not t:
            continue
        if "://" in t:
            hh = host_from_url(t)
            if hh and host_is_under_apex(hh, apex):
                hosts.add(hh)
        elif "." in t and " " not in t:
            n = normalize_host(t)
            if host_is_under_apex(n, apex):
                hosts.add(n)
    inv_domains = sorted(hosts)
    inventory["domains"] = inv_domains
    inventory["domains_count"] = len(inv_domains)


def live_hosts_from_httpx_findings(findings: list[Finding]) -> set[str]:
    """Normalize hostnames from httpx_scanner live_http_service findings."""
    hosts: set[str] = set()
    for f in findings:
        if not isinstance(f, Finding):
            continue
        if f.source_scanner != "httpx_scanner":
            continue
        t = (f.target or "").strip()
        if not t:
            continue
        if "://" in t:
            hh = host_from_url(t)
            if hh:
                hosts.add(hh)
        else:
            hosts.add(normalize_host(t))
    return hosts
