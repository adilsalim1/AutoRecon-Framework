"""
Plugin ordering helpers for WAF-aware and methodology-friendly scan phases.
"""

from __future__ import annotations

from recon.plugins.base import ScannerPlugin


def order_full_scanning_plugins(
    plugins: list[ScannerPlugin],
    *,
    api_endpoint_priority: bool,
) -> list[ScannerPlugin]:
    """Keep httpx first (live probing), then phase-2 ordering on remaining plugins."""
    httpx = [p for p in plugins if p.name == "httpx_scanner"]
    rest = [p for p in plugins if p.name != "httpx_scanner"]
    return httpx + order_phase2_plugins(rest, api_endpoint_priority=api_endpoint_priority)


def order_phase2_plugins(
    plugins: list[ScannerPlugin],
    *,
    api_endpoint_priority: bool,
) -> list[ScannerPlugin]:
    """
    WAF probe first so shared pipeline_runtime can record vendors before aggressive work.
    Optional: move nuclei immediately after waf for API-heavy programs.
    """
    waf = [p for p in plugins if p.name == "wafw00f_scanner"]
    non_waf = [p for p in plugins if p.name != "wafw00f_scanner"]
    if api_endpoint_priority:
        nuclei = [p for p in non_waf if p.name == "nuclei_scanner"]
        others = [p for p in non_waf if p.name != "nuclei_scanner"]
        return waf + nuclei + others
    return waf + non_waf
