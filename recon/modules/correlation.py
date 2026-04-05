"""
Correlate findings into attack-chain narratives (loose coupling — no tool imports).
"""

from __future__ import annotations

from urllib.parse import urlparse

from recon.models.assets import Asset, AssetType
from recon.models.findings import Finding, Severity
from recon.modules.secrets.detector import merge_secret_severity

_SEV_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def _host_key(target: str) -> str:
    t = (target or "").strip()
    if "://" in t:
        try:
            return (urlparse(t).hostname or t).lower()
        except ValueError:
            pass
    return t.lower().split("/")[0].split(":")[0]


def _is_secret_finding(f: Finding) -> bool:
    return f.vulnerability_type.startswith("secret_") or "secret" in f.vulnerability_type


def _is_exposed_endpoint(f: Finding) -> bool:
    if f.source_scanner == "nuclei_scanner":
        return True
    return f.vulnerability_type in (
        "linkfinder_endpoint",
        "ffuf_hit",
        "live_http_service",
    )


def correlate_findings(
    findings: list[Finding],
    assets: list[Asset] | None = None,
) -> list[Finding]:
    """
    Emit synthetic correlated findings when secrets and surface exposure share a host.
    """
    by_host: dict[str, list[Finding]] = {}
    for f in findings:
        by_host.setdefault(_host_key(f.target), []).append(f)

    api_hosts: set[str] = set()
    if assets:
        for a in assets:
            if a.asset_type == AssetType.API:
                api_hosts.add(a.identifier.lower().strip().rstrip("."))

    extra: list[Finding] = []
    for host, group in by_host.items():
        if not host:
            continue
        secrets = [x for x in group if _is_secret_finding(x)]
        exposed = [x for x in group if _is_exposed_endpoint(x)]
        if not secrets or not exposed:
            continue
        top_sec = max(secrets, key=lambda s: _SEV_RANK.get(s.severity, 0))
        new_sev = merge_secret_severity(top_sec.severity, Severity.HIGH)
        if any(s.severity == Severity.CRITICAL for s in secrets):
            new_sev = Severity.CRITICAL
        elif _SEV_RANK.get(new_sev, 0) < _SEV_RANK[Severity.HIGH]:
            new_sev = Severity.HIGH
        path = [
            f"Host {host} has exposed/interesting endpoints",
            f"Secret-class signal: {top_sec.vulnerability_type}",
        ]
        if host in api_hosts:
            new_sev = merge_secret_severity(new_sev, Severity.HIGH)
            path.append("Asset classified as API — prioritize endpoint abuse")
        extra.append(
            Finding(
                target=host,
                vulnerability_type="correlated_attack_chain",
                severity=new_sev,
                evidence={
                    "secret_types": list({s.vulnerability_type for s in secrets})[:10],
                    "exposure_types": list({e.vulnerability_type for e in exposed})[:10],
                },
                source_scanner="correlation_engine",
                title="Correlated: exposure + secret signal on same host",
                description="Review endpoint and secret findings together for exploit paths.",
                attack_path=path,
                exploitability="chained",
                confidence=min(0.9, (top_sec.confidence or 0.5) + 0.15),
            )
        )
    return findings + extra
