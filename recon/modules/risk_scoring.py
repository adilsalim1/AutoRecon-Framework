from __future__ import annotations

from recon.models.assets import Asset, AssetType, Priority
from recon.models.findings import Finding, Severity

_SEV_WEIGHT = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 28.0,
    Severity.MEDIUM: 15.0,
    Severity.LOW: 8.0,
    Severity.INFO: 3.0,
}

_PRI_WEIGHT = {
    Priority.CRITICAL: 12.0,
    Priority.HIGH: 8.0,
    Priority.MEDIUM: 4.0,
    Priority.LOW: 1.0,
}


def _asset_for_finding(assets: list[Asset], f: Finding) -> Asset | None:
    if f.asset_id:
        for a in assets:
            if a.stable_id() == f.asset_id:
                return a
    tid = (f.target or "").lower()
    for a in assets:
        if a.identifier.lower() in tid or tid in a.identifier.lower():
            return a
    return None


def score_finding(f: Finding, assets: list[Asset]) -> float:
    base = _SEV_WEIGHT.get(f.severity, 5.0)
    conf = float(f.confidence or 0.5)
    exposure = 6.0 if (f.source_ref or "").startswith("http") else 2.0
    if f.vulnerability_type.startswith("secret_"):
        base += 10.0
    if f.vulnerability_type == "waf_detected":
        base += 2.0
    a = _asset_for_finding(assets, f)
    pri = _PRI_WEIGHT.get(a.priority, 4.0) if a else 2.0
    if a and a.asset_type in (AssetType.API, AssetType.AUTH):
        pri += 10.0
    return round(base * (0.5 + conf) + exposure + pri, 2)


def apply_risk_scores(findings: list[Finding], assets: list[Asset]) -> list[Finding]:
    for f in findings:
        f.risk_score = score_finding(f, assets)
    return findings
