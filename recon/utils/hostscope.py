"""Reject out-of-scope or path-like hostnames from sloppy tool output (e.g. amass paths)."""

from __future__ import annotations

from urllib.parse import urlparse


def normalize_discovery_hostname(token: str) -> str:
    """Strip paths, ports, schemes; lower-case; drop path segments."""
    t = (token or "").strip()
    if not t:
        return ""
    if "://" in t:
        try:
            h = urlparse(t).hostname
            t = h or t
        except ValueError:
            pass
    t = t.split("/")[0].split(":")[0].strip().lower().rstrip(".")
    return t


def hostname_in_scope(host: str, parent: str) -> bool:
    """
    True if host is the program apex or a subdomain under parent.
    Rejects single-label noise (e.g. amass resource paths) and foreign domains.
    """
    h = host.strip().lower().rstrip(".")
    p = parent.strip().lower().rstrip(".")
    if not h or not p or "*" in h or " " in h:
        return False
    if "/" in h or "\\" in h or h.startswith("."):
        return False
    if h == p:
        return True
    return h.endswith("." + p)
