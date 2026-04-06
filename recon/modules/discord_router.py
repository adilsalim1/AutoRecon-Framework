"""
Map findings and assets to Discord channel keys (vulnerabilities, tech, ports, …).
"""

from __future__ import annotations

from recon.models.assets import Asset, AssetType, Priority
from recon.models.findings import Finding, Severity

# Channel keys — must match DiscordWebhooksConfig field names
CH_VULNERABILITIES = "vulnerabilities"
CH_TECH = "tech"
CH_PORTS = "ports"
CH_ASSETS = "assets"
CH_CRITICAL = "critical"
CH_SECRETS = "secrets"
CH_STAGING = "staging"
CH_SUMMARY = "summary"

# Iteration order for “post the same export to every configured webhook”
ALL_DISCORD_CHANNEL_KEYS: tuple[str, ...] = (
    CH_VULNERABILITIES,
    CH_TECH,
    CH_PORTS,
    CH_ASSETS,
    CH_CRITICAL,
    CH_SECRETS,
    CH_STAGING,
    CH_SUMMARY,
)


def is_critical_host_asset(asset: Asset) -> bool:
    """High-signal hosts for immediate critical-channel alerts."""
    if asset.priority == Priority.CRITICAL:
        return True
    if asset.asset_type in (AssetType.AUTH, AssetType.API):
        return True
    if "takeover" in asset.tags or "high_value" in asset.tags:
        return True
    return False


def is_staging_triage_asset(asset: Asset) -> bool:
    """Lower-noise hosts batched to staging after analysis."""
    if is_critical_host_asset(asset):
        return False
    if asset.asset_type == AssetType.DOMAIN:
        return False
    return asset.priority in (Priority.MEDIUM, Priority.LOW) and asset.asset_type in (
        AssetType.SUBDOMAIN,
        AssetType.WEB,
        AssetType.UNKNOWN,
    )


def route_finding_channel(finding: Finding) -> str:
    """
    Return channel key for a finding (used for routing + buffer selection).
    """
    vt = finding.vulnerability_type.lower()
    scanner = (finding.source_scanner or "").lower()
    sev = finding.severity

    if vt.startswith("secret_") or "secret" in vt or scanner in (
        "url_secret_detector",
        "secret_detector",
    ):
        return CH_SECRETS
    if scanner == "js_analysis" and "secret" in vt:
        return CH_SECRETS

    if sev == Severity.CRITICAL or vt == "correlated_attack_chain":
        return CH_CRITICAL

    if vt == "technology_profile" or scanner in ("whatweb_scanner", "wappalyzer_scanner"):
        return CH_TECH
    if vt == "live_http_service" and scanner == "httpx_scanner":
        ev = finding.evidence or {}
        if ev.get("technologies") or ev.get("tech"):
            return CH_TECH
        return CH_STAGING

    if vt in ("open_tcp_port", "exposed_service") or scanner in (
        "naabu_scanner",
        "nmap_scanner",
    ):
        return CH_PORTS

    if (
        scanner == "nuclei_scanner"
        or "vuln" in vt
        or vt
        in (
            "ffuf_hit",
            "subdomain_takeover_candidate",
            "waf_detected",
            "waf_detection_inconclusive",
            "waf_not_detected",
        )
        or vt.startswith("template")
    ):
        return CH_VULNERABILITIES

    if vt == "linkfinder_endpoint":
        return CH_STAGING

    return CH_STAGING


def finding_immediate_delivery(finding: Finding) -> bool:
    """
    Immediate POST vs batched flush.
    Critical, secrets, and WAF go out immediately; most others batch to reduce spam.
    """
    vt = finding.vulnerability_type.lower()
    sev = finding.severity

    if route_finding_channel(finding) == CH_SECRETS:
        return True
    if sev == Severity.CRITICAL or vt == "correlated_attack_chain":
        return True
    if vt == "waf_detected":
        return True
    # Tech / fingerprint channel: post now (was batched; easy to miss if webhook or flush misconfigured)
    if route_finding_channel(finding) == CH_TECH:
        return True
    return False
