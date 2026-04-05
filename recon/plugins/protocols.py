"""
Integration boundaries for future scanners (ZAP, Burp, custom crawlers).
Implementations stay in separate modules/plugins; reference these Protocols only for typing.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from recon.models.assets import Asset
from recon.models.findings import Finding


@runtime_checkable
class PassiveUrlSource(Protocol):
    """Historical / third-party URL feeds (e.g. gau, wayback)."""

    def collect(self, domain: str, tool_paths: dict[str, str]) -> list[str]: ...


@runtime_checkable
class WebCrawlerIntegration(Protocol):
    """Browserless crawlers (katana, hakrawler, future headless)."""

    def crawl(self, seed_url: str, tool_paths: dict[str, str]) -> list[str]: ...


@runtime_checkable
class DynamicScannerIntegration(Protocol):
    """Placeholder for OWASP ZAP / Burp-driven scans (out-of-band from this repo)."""

    def scan_target(self, target_url: str, options: dict[str, Any]) -> list[Finding]: ...


@runtime_checkable
class JsStaticAnalyzer(Protocol):
    """LinkFinder / Semgrep / custom AST passes over JavaScript text."""

    def analyze_js(self, js_url: str, body: str) -> list[Finding]: ...
