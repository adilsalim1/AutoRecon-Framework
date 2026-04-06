"""
Discord-oriented message bodies: embeds, code blocks, truncation (Discord limits).
"""

from __future__ import annotations

import json
from typing import Any

from recon.models.assets import Asset
from recon.models.findings import Finding, Severity

# Discord limits (embed description max 4096; stay slightly below)
_MAX_DESC = 4080
_MAX_FIELD = 1000
_MAX_codeblock = 900
_MAX_EMBEDS_PER_MESSAGE = 10


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


def _consume_lines_up_to_budget(lines: list[str], budget: int) -> tuple[str, list[str]]:
    """Join leading lines until character budget (for Discord embed description)."""
    if budget <= 0:
        return "", lines
    if not lines:
        return "", []
    buf: list[str] = []
    used = 0
    i = 0
    for i, line in enumerate(lines):
        need = len(line) + (1 if buf else 0)
        if used + need > budget:
            if not buf and need > budget:
                buf.append(line[: max(0, budget - 3)] + "…")
                i += 1
            break
        buf.append(line)
        used += need
    else:
        i = len(lines)
    return "\n".join(buf), lines[i:]


def _export_filename_prefix(domain: str, run_id: str) -> str:
    sdom = "".join(c if c.isalnum() or c in "-._" else "_" for c in (domain or ""))[:80]
    rid = "".join(c if c.isalnum() or c in "-._" else "_" for c in (run_id or ""))[:16]
    return f"{sdom}_{rid}"


def format_surface_inventory_summary_payload(
    inventory: dict[str, Any],
    run_id: str,
    domain: str,
    *,
    channel_label: str = "ASSETS",
) -> dict[str, Any]:
    """Short Discord webhook: counts only; full lists are meant to be sent as attachments."""
    desc = (
        f"**Scope:** `{domain}` · **Run:** `{run_id}`\n\n"
        f"**Unique hosts:** `{inventory.get('domains_count', 0)}`\n"
        f"**URLs:** `{inventory.get('urls_count', 0)}` · "
        f"**Paths:** `{inventory.get('endpoints_count', 0)}`\n\n"
        "_Complete lists are attached (`hosts_domains.txt`, `urls.txt`, "
        "`endpoint_paths.txt`, `inventory_meta.json`)._"
    )[:_MAX_DESC]
    embed = {
        "title": "Surface inventory (full export)",
        "description": desc,
        "color": 0x3498DB,
    }
    return format_webhook_with_embeds(
        f"[{channel_label}] Inventory · `{domain}` · `{run_id}`",
        [embed],
    )


def build_inventory_export_files(
    inventory: dict[str, Any],
    domain: str,
    run_id: str,
) -> list[tuple[str, bytes]]:
    """Plain-text / JSON attachments: full deduped hosts, URLs, paths, and metadata."""
    prefix = _export_filename_prefix(domain, run_id)
    doms = list(inventory.get("domains") or [])
    urls = list(inventory.get("urls") or [])
    paths = list(inventory.get("endpoint_paths") or [])
    meta = {
        "apex": inventory.get("apex"),
        "domain_scope": domain,
        "run_id": run_id,
        "domains_count": inventory.get("domains_count", len(doms)),
        "urls_count": inventory.get("urls_count", len(urls)),
        "endpoints_count": inventory.get("endpoints_count", len(paths)),
    }
    return [
        (f"{prefix}_hosts_domains.txt", "\n".join(doms).encode("utf-8")),
        (f"{prefix}_urls.txt", "\n".join(urls).encode("utf-8")),
        (f"{prefix}_endpoint_paths.txt", "\n".join(paths).encode("utf-8")),
        (f"{prefix}_inventory_meta.json", json.dumps(meta, indent=2).encode("utf-8")),
    ]


def build_final_scan_export_files(
    findings: list[Finding],
    assets: list[Asset],
    run_id: str,
    domain: str,
) -> list[tuple[str, bytes]]:
    """End-of-run attachments: NDJSON findings + deduped asset hostnames."""
    prefix = _export_filename_prefix(domain, run_id)
    lines = [json.dumps(f.to_dict(), default=str) for f in findings]
    findings_bytes = "\n".join(lines).encode("utf-8")
    idents = sorted(
        {a.identifier.strip() for a in assets if (a.identifier or "").strip()}
    )
    assets_bytes = "\n".join(idents).encode("utf-8")
    summary = {
        "domain_scope": domain,
        "run_id": run_id,
        "findings_count": len(findings),
        "assets_count": len(assets),
    }
    return [
        (f"{prefix}_findings.jsonl", findings_bytes),
        (f"{prefix}_assets.txt", assets_bytes),
        (f"{prefix}_run_summary.json", json.dumps(summary, indent=2).encode("utf-8")),
    ]


def format_surface_inventory_payload(
    inventory: dict[str, Any],
    run_id: str,
    domain: str,
) -> dict[str, Any]:
    """Discord webhook: deduplicated domains, URL counts, samples (hosts from URLs included)."""
    doms = inventory.get("domains") or []
    urls = inventory.get("urls") or []
    sample_hosts = "\n".join(f"- `{h}`" for h in doms[:35])
    if len(doms) > 35:
        sample_hosts += f"\n_…+{len(doms) - 35} hosts_"
    sample_urls = "\n".join(f"- `{u[:180]}`" for u in urls[:12])
    if len(urls) > 12:
        sample_urls += f"\n_…+{len(urls) - 12} URLs_"
    paths = inventory.get("endpoint_paths") or []
    sample_paths = "\n".join(f"- `{p[:120]}`" for p in paths[:20])
    if len(paths) > 20:
        sample_paths += f"\n_…+{len(paths) - 20} paths_"
    desc = (
        f"**Scope:** `{domain}` · **Run:** `{run_id}`\n\n"
        f"**Unique hosts:** `{inventory.get('domains_count', 0)}` "
        f"(discovery + URL netloc + enum)\n"
        f"**URLs:** `{inventory.get('urls_count', 0)}` · "
        f"**Paths:** `{inventory.get('endpoints_count', 0)}`\n\n"
        f"**Hosts (sample):**\n{sample_hosts or '—'}\n\n"
        f"**URLs (sample):**\n{sample_urls or '—'}\n\n"
        f"**Paths (sample):**\n{sample_paths or '—'}"
    )[:_MAX_DESC]
    embed = {
        "title": "Surface inventory (deduplicated)",
        "description": desc,
        "color": 0x3498DB,
    }
    return format_webhook_with_embeds(
        f"[ASSETS] Inventory · `{domain}` · `{run_id}`",
        [embed],
    )


def format_asset_discovery_payloads(
    assets: list[Asset],
    run_id: str,
    domain: str,
) -> list[dict[str, Any]]:
    """
    Full host list split across Discord embeds (4096 chars each), then across
    multiple webhook posts if needed (10 embeds max per POST).
    """
    by_type: dict[str, int] = {}
    for a in assets:
        k = a.asset_type.value
        by_type[k] = by_type.get(k, 0) + 1
    lines = [
        f"`{a.identifier}` · _{a.asset_type.value}_ · **{a.priority.value}**"
        for a in assets
        if (a.identifier or "").strip()
    ]
    prefix = (
        f"**Scope:** `{domain}`\n**Run:** `{run_id}`\n**Total:** `{len(assets)}`\n\n"
        f"**By type:**\n{_code_block(json.dumps(by_type, indent=2), 'json')}\n\n"
    )
    hdr_main = "**All hosts:**\n"
    hdr_cont = f"**All hosts ·** `{domain}` **(continued)**\n"

    embeds: list[dict[str, Any]] = []
    remaining = lines[:]
    idx = 0
    while True:
        if idx == 0:
            head = prefix + hdr_main
        else:
            if not remaining:
                break
            head = hdr_cont
        room = max(200, _MAX_DESC - len(head))
        body, remaining = _consume_lines_up_to_budget(remaining, room)
        if idx == 0 and not body:
            body = "_No assets_" if not lines else body
        if not body:
            break
        title = "Asset discovery" if idx == 0 else f"Asset discovery · continued ({idx + 1})"
        embeds.append(
            {
                "title": title[:256],
                "description": (head + body)[:_MAX_DESC],
                "color": 0x2ECC71,
            }
        )
        idx += 1
        if idx > 500:
            break

    if not embeds:
        embeds = [
            {
                "title": "Asset discovery",
                "description": (prefix + hdr_main + "_No assets_")[:_MAX_DESC],
                "color": 0x2ECC71,
            }
        ]

    total_msgs = (len(embeds) + _MAX_EMBEDS_PER_MESSAGE - 1) // _MAX_EMBEDS_PER_MESSAGE
    payloads: list[dict[str, Any]] = []
    for mi in range(total_msgs):
        batch = embeds[mi * _MAX_EMBEDS_PER_MESSAGE : (mi + 1) * _MAX_EMBEDS_PER_MESSAGE]
        content = (
            f"[ASSETS] **{len(assets)}** host(s) · `{domain}` · run `{run_id}`"
        )
        if total_msgs > 1:
            content += f" · _part {mi + 1}/{total_msgs}_"
        payloads.append(format_webhook_with_embeds(content, batch))
    return payloads


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
