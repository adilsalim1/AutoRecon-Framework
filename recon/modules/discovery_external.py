from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

from recon.core.logger import get_logger
from recon.models.assets import Asset, AssetType
from recon.modules.discovery import DiscoveryProvider
from recon.utils.tool_runner import resolve_binary, run_tool

log = get_logger("discovery")


def _host_asset(host: str, parent: str, source: str, **meta: object) -> Asset | None:
    host = host.strip().lower().rstrip(".")
    if not host or "*" in host or " " in host:
        return None
    at = AssetType.DOMAIN if host == parent else AssetType.SUBDOMAIN
    return Asset(
        identifier=host,
        asset_type=at,
        parent_domain=parent,
        metadata={"source": source, **meta},
    )


class SubfinderDiscoveryProvider(DiscoveryProvider):
    def __init__(self, tool_paths: dict[str, str], timeout: int = 300) -> None:
        self._bin = resolve_binary(tool_paths, "subfinder", "subfinder")
        self._timeout = timeout

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        proc = run_tool(
            [self._bin, "-d", parent, "-silent", "-json"],
            timeout=self._timeout,
        )
        out: list[Asset] = []
        if proc.returncode != 0 and not proc.stdout.strip():
            log.warning("subfinder exit=%s stderr=%s", proc.returncode, proc.stderr[:300])
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            host: str | None = None
            try:
                obj = json.loads(line)
                host = obj.get("host") or obj.get("input")
            except json.JSONDecodeError:
                host = line
            if host:
                a = _host_asset(host, parent, "subfinder")
                if a:
                    out.append(a)
        return out


class AssetfinderDiscoveryProvider(DiscoveryProvider):
    def __init__(self, tool_paths: dict[str, str], timeout: int = 300) -> None:
        self._bin = resolve_binary(tool_paths, "assetfinder", "assetfinder")
        self._timeout = timeout

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        proc = run_tool([self._bin, parent], timeout=self._timeout)
        if proc.returncode != 0:
            log.warning("assetfinder exit=%s stderr=%s", proc.returncode, proc.stderr[:300])
        out: list[Asset] = []
        for line in proc.stdout.splitlines():
            a = _host_asset(line, parent, "assetfinder")
            if a:
                out.append(a)
        return out


class AmassPassiveDiscoveryProvider(DiscoveryProvider):
    """Passive enumeration only (no brute force). CLI varies by Amass major version."""

    def __init__(self, tool_paths: dict[str, str], timeout: int = 300) -> None:
        self._bin = resolve_binary(tool_paths, "amass", "amass")
        self._timeout = timeout

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        for args in (
            ["enum", "-passive", "-d", parent, "-nocolor"],
            ["enum", "-passive", "-d", parent],
        ):
            proc = run_tool([self._bin, *args], timeout=self._timeout)
            if proc.stdout.strip():
                break
        else:
            proc = run_tool([self._bin, "enum", "-passive", "-d", parent], timeout=self._timeout)
        if proc.returncode != 0 and not proc.stdout.strip():
            log.warning("amass exit=%s stderr=%s", proc.returncode, proc.stderr[:300])
        out: list[Asset] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or " " in line and "." not in line.split()[0]:
                continue
            host = line.split()[0].lower().rstrip(".")
            a = _host_asset(host, parent, "amass_passive")
            if a:
                out.append(a)
        return out


class CrtShDiscoveryProvider(DiscoveryProvider):
    """Certificate Transparency via crt.sh JSON API (no local binary)."""

    def __init__(self, timeout: int = 120) -> None:
        self._timeout = timeout

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        q = urllib.parse.quote(f"%.{parent}")
        url = f"https://crt.sh/?q={q}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "AutoRecon-Framework/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as e:
            log.warning("crt.sh request failed: %s", e)
            return []
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("crt.sh returned non-JSON")
            return []
        if not isinstance(rows, list):
            return []
        out: list[Asset] = []
        for row in rows:
            nv = row.get("name_value") or ""
            for part in re.split(r"[\n,]", nv):
                a = _host_asset(part, parent, "crtsh")
                if a:
                    out.append(a)
        return out


class WaybackurlsDiscoveryProvider(DiscoveryProvider):
    """Historical URLs → unique hostnames as web-oriented assets."""

    def __init__(self, tool_paths: dict[str, str], timeout: int = 300) -> None:
        self._bin = resolve_binary(tool_paths, "waybackurls", "waybackurls")
        self._timeout = timeout

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        proc = run_tool([self._bin, parent], timeout=self._timeout)
        if proc.returncode != 0:
            log.warning("waybackurls exit=%s stderr=%s", proc.returncode, proc.stderr[:300])
        hosts: set[str] = set()
        for line in proc.stdout.splitlines():
            u = line.strip()
            if not u.startswith("http"):
                continue
            try:
                h = urlparse(u).hostname
            except Exception:
                continue
            if h:
                hosts.add(h.lower().rstrip("."))
        out: list[Asset] = []
        for h in hosts:
            if parent not in h and not h.endswith("." + parent):
                continue
            out.append(
                Asset(
                    identifier=h,
                    asset_type=AssetType.WEB,
                    parent_domain=parent,
                    metadata={"source": "waybackurls"},
                )
            )
        return out


class ShuffleDnsDiscoveryProvider(DiscoveryProvider):
    """Active brute via shuffledns when wordlist + resolvers are configured."""

    def __init__(
        self,
        tool_paths: dict[str, str],
        wordlist: str,
        resolvers: str,
        timeout: int = 600,
    ) -> None:
        self._bin = resolve_binary(tool_paths, "shuffledns", "shuffledns")
        self._wordlist = wordlist
        self._resolvers = resolvers
        self._timeout = timeout

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        if not self._wordlist or not self._resolvers:
            log.info("shuffledns skipped: set discovery.wordlist and discovery.resolvers")
            return []
        proc = run_tool(
            [
                self._bin,
                "-d",
                parent,
                "-list",
                self._wordlist,
                "-r",
                self._resolvers,
                "-silent",
            ],
            timeout=self._timeout,
        )
        if proc.returncode != 0:
            log.warning("shuffledns exit=%s stderr=%s", proc.returncode, proc.stderr[:300])
        out: list[Asset] = []
        for line in proc.stdout.splitlines():
            a = _host_asset(line, parent, "shuffledns")
            if a:
                out.append(a)
        return out


class MassDnsDiscoveryProvider(DiscoveryProvider):
    """Placeholder: massdns needs crafted inputs; use shuffledns or custom workflows."""

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        log.info("massdns provider is a stub — integrate via custom DiscoveryProvider or pipeline step")
        return []
