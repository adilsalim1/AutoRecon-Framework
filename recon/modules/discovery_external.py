from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse
from pathlib import Path

from recon.core.logger import get_logger
from recon.models.assets import Asset, AssetType
from recon.modules.discovery import DiscoveryProvider
from recon.utils.hostscope import hostname_in_scope, normalize_discovery_hostname
from recon.utils.tool_runner import resolve_binary, run_tool

log = get_logger("discovery")


def _host_asset(host: str, parent: str, source: str, **meta: object) -> Asset | None:
    parent_n = parent.strip().lower().rstrip(".")
    host = normalize_discovery_hostname(host)
    if not host or not hostname_in_scope(host, parent_n):
        return None
    at = AssetType.DOMAIN if host == parent_n else AssetType.SUBDOMAIN
    return Asset(
        identifier=host,
        asset_type=at,
        parent_domain=parent,
        metadata={"source": source, **meta},
    )


class SubfinderDiscoveryProvider(DiscoveryProvider):
    def __init__(
        self,
        tool_paths: dict[str, str],
        timeout: int = 300,
        stream_output: bool = True,
    ) -> None:
        self._bin = resolve_binary(tool_paths, "subfinder", "subfinder")
        self._timeout = timeout
        self._stream = stream_output

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        log.info("subfinder: enumerating %s", parent)
        proc = run_tool(
            [self._bin, "-d", parent, "-silent", "-json"],
            timeout=self._timeout,
            live_output=self._stream,
            live_prefix="subfinder",
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
        log.info("subfinder: parsed %s hostnames for %s", len(out), parent)
        return out


class AssetfinderDiscoveryProvider(DiscoveryProvider):
    def __init__(
        self,
        tool_paths: dict[str, str],
        timeout: int = 300,
        stream_output: bool = True,
    ) -> None:
        self._bin = resolve_binary(tool_paths, "assetfinder", "assetfinder")
        self._timeout = timeout
        self._stream = stream_output

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        log.info("assetfinder: querying %s", parent)
        proc = run_tool(
            [self._bin, parent],
            timeout=self._timeout,
            live_output=self._stream,
            live_prefix="assetfinder",
        )
        if proc.returncode != 0:
            log.warning("assetfinder exit=%s stderr=%s", proc.returncode, proc.stderr[:300])
        out: list[Asset] = []
        for line in proc.stdout.splitlines():
            a = _host_asset(line, parent, "assetfinder")
            if a:
                out.append(a)
        log.info("assetfinder: parsed %s hosts for %s", len(out), parent)
        return out


class AmassPassiveDiscoveryProvider(DiscoveryProvider):
    """Passive enumeration only (no brute force). CLI varies by Amass major version."""

    def __init__(
        self,
        tool_paths: dict[str, str],
        timeout: int = 300,
        stream_output: bool = True,
    ) -> None:
        self._bin = resolve_binary(tool_paths, "amass", "amass")
        self._timeout = timeout
        self._stream = stream_output

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        log.info(
            "amass (passive): enumerating %s (timeout %ss)",
            parent,
            self._timeout,
        )
        # Amass redraws a TTY progress bar; with piped stderr every tick becomes a new
        # "[amass:stderr]" line. Stream only pollutes logs — output is still captured.
        stream_amass = False
        arg_variants = (
            ["enum", "-passive", "-d", parent, "-nocolor"],
            ["enum", "-passive", "-d", parent],
        )
        proc = None
        for args in arg_variants:
            proc = run_tool(
                [self._bin, *args],
                timeout=self._timeout,
                live_output=stream_amass,
                live_prefix="amass",
            )
            if proc.stdout.strip():
                break
            # exit 124 = framework subprocess timeout — don't chain another full wait
            if proc.returncode == 124:
                log.warning(
                    "amass timed out after %ss; set discovery.amass_timeout_seconds higher if needed",
                    self._timeout,
                )
                break
        else:
            proc = run_tool(
                [self._bin, "enum", "-passive", "-d", parent],
                timeout=self._timeout,
                live_output=stream_amass,
                live_prefix="amass",
            )
        if proc is None:
            return []
        if proc.returncode != 0 and not proc.stdout.strip() and proc.returncode != 124:
            log.warning(
                "amass exit=%s stderr=%s",
                proc.returncode,
                (proc.stderr or "")[:300],
            )
        out: list[Asset] = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith("[") or line.startswith("#"):
                continue
            token = line.split()[0]
            # Amass prints paths/dat dirs (e.g. language_classifier/) — not hostnames
            if "/" in token or not any(c.isalnum() for c in token):
                continue
            a = _host_asset(token, parent, "amass_passive")
            if a:
                out.append(a)
        log.info("amass: parsed %s hosts for %s", len(out), parent)
        return out


class CrtShDiscoveryProvider(DiscoveryProvider):
    """Certificate Transparency via crt.sh JSON API (no local binary)."""

    def __init__(self, timeout: int = 120) -> None:
        self._timeout = timeout

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        q = urllib.parse.quote(f"%.{parent}")
        url = f"https://crt.sh/?q={q}&output=json"
        log.info("crt.sh: fetching certificate transparency for %s", parent)
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
        log.info("crt.sh: received %s CT rows for %s", len(rows), parent)
        out: list[Asset] = []
        for row in rows:
            nv = row.get("name_value") or ""
            for part in re.split(r"[\n,]", nv):
                a = _host_asset(part, parent, "crtsh")
                if a:
                    out.append(a)
        log.info("crt.sh: deduped to %s assets for %s", len(out), parent)
        return out


class WaybackurlsDiscoveryProvider(DiscoveryProvider):
    """Historical URLs → unique hostnames as web-oriented assets."""

    def __init__(
        self,
        tool_paths: dict[str, str],
        timeout: int = 300,
        stream_output: bool = True,
    ) -> None:
        self._bin = resolve_binary(tool_paths, "waybackurls", "waybackurls")
        self._timeout = timeout
        self._stream = stream_output

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        log.info("waybackurls: fetching historical URLs for %s", parent)
        proc = run_tool(
            [self._bin, parent],
            timeout=self._timeout,
            live_output=self._stream,
            live_prefix="waybackurls",
        )
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
        log.info("waybackurls: %s in-scope hosts for %s", len(out), parent)
        return out


class ShuffleDnsDiscoveryProvider(DiscoveryProvider):
    """Active brute via shuffledns when wordlist + resolvers are configured."""

    def __init__(
        self,
        tool_paths: dict[str, str],
        wordlist: str,
        resolvers: str,
        timeout: int = 600,
        stream_output: bool = True,
    ) -> None:
        self._bin = resolve_binary(tool_paths, "shuffledns", "shuffledns")
        self._wordlist = wordlist
        self._resolvers = resolvers
        self._timeout = timeout
        self._stream = stream_output

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        if not self._wordlist or not self._resolvers:
            log.info("shuffledns skipped: set discovery.wordlist and discovery.resolvers")
            return []
        log.info("shuffledns: brute %s (wordlist + resolvers)", parent)
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
            live_output=self._stream,
            live_prefix="shuffledns",
        )
        if proc.returncode != 0:
            log.warning("shuffledns exit=%s stderr=%s", proc.returncode, proc.stderr[:300])
        out: list[Asset] = []
        for line in proc.stdout.splitlines():
            a = _host_asset(line, parent, "shuffledns")
            if a:
                out.append(a)
        log.info("shuffledns: %s hosts for %s", len(out), parent)
        return out


class MassDnsDiscoveryProvider(DiscoveryProvider):
    """Placeholder: massdns needs crafted inputs; use shuffledns or custom workflows."""

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        log.info("massdns provider is a stub — integrate via custom DiscoveryProvider or pipeline step")
        return []


def _github_subdomains_has_credentials() -> bool:
    """github-subdomains requires -t, GITHUB_TOKEN, or a `.tokens` file in cwd (upstream behavior)."""
    if (os.environ.get("GITHUB_TOKEN") or "").strip():
        return True
    try:
        return Path(".tokens").is_file()
    except OSError:
        return False


class GithubSubdomainsDiscoveryProvider(DiscoveryProvider):
    """
    [gwen001/github-subdomains](https://github.com/gwen001/github-subdomains) — code search on GitHub for hostnames.
    Requires a GitHub token: `GITHUB_TOKEN` env var (e.g. in `.env`), or `.tokens` in the process cwd.
    """

    def __init__(
        self,
        tool_paths: dict[str, str],
        timeout: int = 600,
        stream_output: bool = True,
    ) -> None:
        self._bin = resolve_binary(tool_paths, "github_subdomains", "github-subdomains")
        self._timeout = max(timeout, 120)
        self._stream = stream_output

    def discover(self, domain: str, expand_subdomains: bool = True) -> list[Asset]:
        parent = domain.strip().lower().rstrip(".")
        if not _github_subdomains_has_credentials():
            log.info(
                "github-subdomains skipped: no GITHUB_TOKEN and no `.tokens` in cwd — "
                "add `GITHUB_TOKEN=...` to `.env` or see https://github.com/gwen001/github-subdomains"
            )
            return []
        log.info("github-subdomains: searching GitHub code for %s", parent)
        proc = run_tool(
            [self._bin, "-d", parent, "-raw"],
            timeout=self._timeout,
            live_output=self._stream,
            live_prefix="github-subdomains",
        )
        if proc.returncode != 0 and not proc.stdout.strip():
            log.warning(
                "github-subdomains exit=%s stderr=%s",
                proc.returncode,
                (proc.stderr or "")[:500],
            )
        out: list[Asset] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or " " in line:
                continue
            a = _host_asset(line, parent, "github_subdomains")
            if a:
                out.append(a)
        log.info("github-subdomains: parsed %s hosts for %s", len(out), parent)
        return out
