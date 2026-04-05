"""
Discord-oriented message bodies: embeds, code blocks, truncation (Discord limits).
"""

from __future__ import annotations

import json
from typing import Any

from recon.models.assets import Asset
from recon.models.findings import Finding, Severity

# Discord limits
_MAX_DESC = 4000
_MAX_FIELD = 1000
_MAX_codeblock = 900


def _code_block(content: str, lang: str = "json") -> str:
    c = (content or "").strip()
    if len(c) > _MAX_codeblock:
        c = c[: _MAX_codeblock - 20] + "\n…(truncated)"
    return f"```{lang}\n{c}\n```"


def _severity_color(sev: Severity) -> int:
    return {
        Severity.CRITICAL: 0xE74C3C,
        Severity.HIGH: 0xE67E22,
        Severity.MEDIUM: 0xF1C40F,
        Severity.LOW: 0x3498DB,
        Severity.INFO: 0x95A5A6,
    }.get(sev, 0x95A5A6)


def format_finding_embed(f: Finding, run_id: str, domain: str) -> dict[str, Any]:
    """Single embed dict (not full webhook payload)."""
    title = (f.title or f.vulnerability_type.replace("_", " ")).strip()[:256]
    if f.vulnerability_type == "waf_detected":
        title = "WAF detected"
        vendor = f.evidence.get("waf_vendor") or f.evidence.get("vendor_hint") or "unknown"
        desc_lines = [
            f"**Target:** `{f.target}`",
            f"**WAF:** `{vendor}`",
            f"**Severity:** `{f.severity.value}`",
            f"**Run:** `{run_id}` · **Scope:** `{domain}`",
        ]
    else:
        desc_lines = [
            f"**Target:** `{f.target}`",
            f"**Severity:** `{f.severity.value}`",
            f"**Type:** `{f.vulnerability_type}`",
            f"**Scanner:** `{f.source_scanner}`",
        ]
        if f.source_ref:
            desc_lines.append(f"**Source:** `{f.source_ref[:400]}`")
        if f.risk_score is not None:
            desc_lines.append(f"**Risk score:** `{f.risk_score}`")
        if f.confidence is not None:
            desc_lines.append(f"**Confidence:** `{f.confidence}`")
        if f.attack_path:
            desc_lines.append("**Attack path:** " + " → ".join(f"_{p}_" for p in f.attack_path[:6]))
        if f.description:
            desc_lines.append(f"**Detail:** {f.description[:800]}")
    desc = "\n".join(desc_lines)[:_MAX_DESC]
    fields: list[dict[str, str]] = []
    ev = f.evidence
    if isinstance(ev, dict) and ev:
        fields.append(
            {
                "name": "Evidence",
                "value": _code_block(json.dumps(ev, indent=2, default=str), "json")[
                    :_MAX_FIELD
                ],
                "inline": False,
            }
        )
    return {
        "title": title,
        "description": desc,
        "color": _severity_color(f.severity),
        "fields": fields[:25],
    }


def format_webhook_with_embeds(
    content: str,
    embeds: list[dict[str, Any]],
    *,
    username: str | None = "AutoRecon",
) -> dict[str, Any]:
    out: dict[str, Any] = {"content": content[:2000]}
    if username:
        out["username"] = username
    if embeds:
        out["embeds"] = embeds[:10]
    return out


def format_asset_discovery_payload(
    assets: list[Asset],
    run_id: str,
    domain: str,
    *,
    max_list: int = 40,
) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    for a in assets:
        k = a.asset_type.value
        by_type[k] = by_type.get(k, 0) + 1
    lines = [f"`{a.identifier}` · _{a.asset_type.value}_ · **{a.priority.value}**" for a in assets[:max_list]]
    extra = len(assets) - max_list
    body = "\n".join(lines) if lines else "_No assets_"
    if extra > 0:
        body += f"\n\n_…and {extra} more_"
    desc = (
        f"**Scope:** `{domain}`\n**Run:** `{run_id}`\n**Total:** `{len(assets)}`\n\n"
        f"**By type:**\n{_code_block(json.dumps(by_type, indent=2), 'json')}\n\n"
        f"**Sample:**\n{body[:2800]}"
    )[:_MAX_DESC]
    embed = {
        "title": "Asset discovery",
        "description": desc,
        "color": 0x2ECC71,
    }
    return format_webhook_with_embeds(
        f"[ASSETS] **{len(assets)}** host(s) · `{domain}` · run `{run_id}`",
        [embed],
    )


def format_critical_subdomain_payload(asset: Asset, run_id: str, domain: str) -> dict[str, Any]:
    meta = _code_block(json.dumps(asset.metadata, indent=2, default=str), "json")[:_MAX_FIELD]
    embed = {
        "title": "Critical / high-value host",
        "description": (
            f"**Host:** `{asset.identifier}`\n"
            f"**Type:** `{asset.asset_type.value}`\n"
            f"**Priority:** `{asset.priority.value}`\n"
            f"**Tags:** `{', '.join(sorted(asset.tags)) or '—'}`\n"
            f"**Scope:** `{domain}` · **Run:** `{run_id}`"
        )[:_MAX_DESC],
        "color": 0xC0392B,
        "fields": [{"name": "Metadata", "value": meta, "inline": False}],
    }
    return format_webhook_with_embeds(
        f"[CRITICAL] `{asset.identifier}`",
        [embed],
    )


def format_staging_asset_payload(assets: list[Asset], run_id: str, domain: str) -> dict[str, Any]:
    lines = [f"`{a.identifier}` ({a.asset_type.value}, {a.priority.value})" for a in assets[:50]]
    extra = len(assets) - 50
    text = "\n".join(lines)
    if extra > 0:
        text += f"\n_…+{extra} more_"
    embed = {
        "title": "Staging triage (lower-noise surface)",
        "description": (
            f"**Scope:** `{domain}`\n**Run:** `{run_id}`\n**Count:** `{len(assets)}`\n\n{text[:3500]}"
        )[:_MAX_DESC],
        "color": 0x7F8C8D,
    }
    return format_webhook_with_embeds(
        f"[STAGING] **{len(assets)}** host(s) · `{domain}`",
        [embed],
    )


def format_tech_profile_payload(
    *,
    asset: Asset | None,
    finding: Finding | None,
    run_id: str,
    domain: str,
) -> dict[str, Any]:
    if finding is not None:
        emb = format_finding_embed(finding, run_id, domain)
        emb["title"] = f"Tech profile · {finding.evidence.get('profiler', 'unknown')}"
        return format_webhook_with_embeds(
            f"[TECH] `{finding.target}`",
            [emb],
        )
    if asset is None:
        return format_webhook_with_embeds("[TECH] (no data)", [])
    meta = _code_block(json.dumps(asset.metadata, indent=2, default=str), "json")
    embed = {
        "title": "Technology surface (asset)",
        "description": (
            f"**Host:** `{asset.identifier}`\n"
            f"**Type:** `{asset.asset_type.value}`\n"
            f"**Scope:** `{domain}` · **Run:** `{run_id}`\n\n{meta}"
        )[:_MAX_DESC],
        "color": 0x3498DB,
    }
    return format_webhook_with_embeds(f"[TECH] `{asset.identifier}`", [embed])


def format_ports_payload(finding: Finding, run_id: str, domain: str) -> dict[str, Any]:
    emb = format_finding_embed(finding, run_id, domain)
    emb["title"] = "Port / service observation"
    emb["color"] = 0x9B59B6
    return format_webhook_with_embeds(f"[PORTS] `{finding.target}`", [emb])


def format_summary_payload(
    report: dict[str, Any],
    run_id: str,
    domain: str,
    *,
    total_assets: int,
    findings: list[Finding],
) -> dict[str, Any]:
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    summary_obj = {
        "run_id": run_id,
        "domain": domain,
        "total_assets": total_assets,
        "total_findings": len(findings),
        "by_severity": by_sev,
        **{k: v for k, v in report.items() if k not in ("run_id", "domain")},
    }
    desc = (
        f"**Run:** `{run_id}`\n**Scope:** `{domain}`\n\n"
        f"**Assets:** `{total_assets}`\n**Findings:** `{len(findings)}`\n\n"
        f"{_code_block(json.dumps(by_sev, indent=2), 'json')}\n\n"
        f"**Report keys:** {_code_block(json.dumps(list(report.keys()), indent=2), 'json')}"
    )[:_MAX_DESC]
    embed = {
        "title": "Pipeline summary",
        "description": desc,
        "color": 0x1ABC9C,
    }
    return format_webhook_with_embeds(
        f"[SUMMARY] `{domain}` complete · `{len(findings)}` finding(s)",
        [embed],
    )
