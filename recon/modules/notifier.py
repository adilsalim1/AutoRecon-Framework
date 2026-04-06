from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from recon.core.config_loader import AppConfig
from recon.core.logger import get_logger
from recon.models.assets import Asset
from recon.models.findings import Finding, Severity
from recon.modules.discord_delivery import (
    multipart_jobs_for_webhook,
    run_discord_multipart_posts_sync,
    run_discord_posts_sync,
)
from recon.modules.discord_router import (
    ALL_DISCORD_CHANNEL_KEYS,
    CH_ASSETS,
    CH_CRITICAL,
    CH_PORTS,
    CH_SECRETS,
    CH_STAGING,
    CH_SUMMARY,
    CH_TECH,
    CH_VULNERABILITIES,
    finding_immediate_delivery,
    route_finding_channel,
)
from recon.modules.message_formatter import (
    build_final_scan_export_files,
    build_inventory_export_files,
    format_asset_discovery_payloads,
    format_critical_subdomain_payload,
    format_finding_embed,
    format_ports_payload,
    format_staging_asset_payload,
    format_summary_payload,
    format_surface_inventory_payload,
    format_surface_inventory_summary_payload,
    format_tech_profile_payload,
    format_webhook_with_embeds,
)

log = get_logger("notifier")

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_DISCORD_COLORS = {
    Severity.CRITICAL: 0xE74C3C,
    Severity.HIGH: 0xE67E22,
    Severity.MEDIUM: 0xF1C40F,
    Severity.LOW: 0x3498DB,
    Severity.INFO: 0x95A5A6,
}


def _is_discord_webhook(url: str) -> bool:
    u = (url or "").lower()
    return "discord.com/api/webhooks" in u or "discordapp.com/api/webhooks" in u


@dataclass
class WebhookNotifier:
    webhook_url: str
    min_severity: Severity = Severity.HIGH
    batch_summaries: bool = True
    deduplicate: bool = True
    discord_rich_embeds: bool = True
    alert_waf_detection: bool = True
    min_risk_score: float | None = None
    _sent_keys: set[str] = field(default_factory=set, repr=False)

    def _meets_threshold(self, f: Finding) -> bool:
        return _SEVERITY_ORDER.get(f.severity, 0) >= _SEVERITY_ORDER.get(self.min_severity, 0)

    def _eligible(self, f: Finding) -> bool:
        if self._meets_threshold(f):
            return True
        if self.alert_waf_detection and f.vulnerability_type == "waf_detected":
            return True
        return False

    def _passes_risk(self, f: Finding) -> bool:
        if self.min_risk_score is None:
            return True
        if f.vulnerability_type == "waf_detected":
            return True
        return float(f.risk_score or 0.0) >= self.min_risk_score

    def notify(
        self,
        findings: list[Finding],
        run_id: str,
        domain: str,
        *,
        total_assets: int = 0,
    ) -> None:
        if not self.webhook_url:
            log.info("webhook not configured; skipping alerts")
            return
        candidates = [f for f in findings if self._eligible(f) and self._passes_risk(f)]
        if self.deduplicate:
            fresh: list[Finding] = []
            for f in candidates:
                ch = route_finding_channel(f)
                k = f"{ch}:{f.discord_notify_dedupe_key(ch)}"
                if k in self._sent_keys:
                    continue
                self._sent_keys.add(k)
                fresh.append(f)
            candidates = fresh
        if not candidates:
            return
        if self.batch_summaries:
            if self.discord_rich_embeds and _is_discord_webhook(self.webhook_url):
                payload = self._discord_batch_payload(
                    run_id, domain, candidates, total_assets=total_assets
                )
            else:
                payload = self._batch_payload(run_id, domain, candidates, total_assets=total_assets)
            self._post(payload)
        else:
            for f in candidates:
                if self.discord_rich_embeds and _is_discord_webhook(self.webhook_url):
                    self._post(self._discord_single_payload(run_id, domain, f))
                else:
                    self._post(self._single_payload(run_id, domain, f))

    def _summary_text(
        self,
        run_id: str,
        domain: str,
        findings: list[Finding],
        *,
        total_assets: int,
    ) -> str:
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        parts = [
            f"**Run** `{run_id}` · **Domain** `{domain}`",
            f"**Assets** {total_assets} · **Alerted findings** {len(findings)}",
            "**By severity:** " + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())),
        ]
        return "\n".join(parts)

    def _single_payload(self, run_id: str, domain: str, f: Finding) -> dict[str, Any]:
        return {
            "event": "recon.finding",
            "run_id": run_id,
            "domain": domain,
            "finding": f.to_dict(),
        }

    def _batch_payload(
        self,
        run_id: str,
        domain: str,
        findings: list[Finding],
        *,
        total_assets: int,
    ) -> dict[str, Any]:
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        return {
            "event": "recon.batch",
            "run_id": run_id,
            "domain": domain,
            "count": len(findings),
            "by_severity": by_sev,
            "summary": self._summary_text(
                run_id, domain, findings, total_assets=total_assets
            ),
            "findings": [f.to_dict() for f in findings],
        }

    def _discord_single_payload(self, run_id: str, domain: str, f: Finding) -> dict[str, Any]:
        emb = self._finding_to_embed(f, run_id, domain)
        title = emb.pop("_title", "Finding")
        return {
            "content": f"[{title}]",
            "embeds": [emb],
        }

    def _discord_batch_payload(
        self,
        run_id: str,
        domain: str,
        findings: list[Finding],
        *,
        total_assets: int,
    ) -> dict[str, Any]:
        waf_first = sorted(
            findings,
            key=lambda x: (0 if x.vulnerability_type == "waf_detected" else 1, -_SEVERITY_ORDER.get(x.severity, 0)),
        )
        embeds: list[dict[str, Any]] = []
        for f in waf_first[:10]:
            e = self._finding_to_embed(f, run_id, domain)
            e.pop("_title", None)
            embeds.append(e)
        summary = self._summary_text(
            run_id, domain, findings, total_assets=total_assets
        )
        return {
            "content": f"[ALERT] Recon batch `{run_id}`\n{summary}",
            "embeds": embeds,
        }

    def _finding_to_embed(self, f: Finding, run_id: str, domain: str) -> dict[str, Any]:
        color = _DISCORD_COLORS.get(f.severity, 0x95A5A6)
        if f.vulnerability_type == "waf_detected":
            title = "[ALERT] WAF Detected"
            vendor = f.evidence.get("waf_vendor") or f.evidence.get("vendor_hint") or "unknown"
            desc = (
                f"**Target:** {f.target}\n**WAF:** {vendor}\n"
                f"**Severity:** {f.severity.value}\n**Run:** `{run_id}` / `{domain}`"
            )
        else:
            title = f.vulnerability_type.replace("_", " ").title()[:250]
            desc_lines = [
                f"**Target:** {f.target}",
                f"**Severity:** {f.severity.value}",
                f"**Scanner:** {f.source_scanner}",
            ]
            if f.source_ref:
                desc_lines.append(f"**Source:** {f.source_ref[:500]}")
            if f.risk_score is not None:
                desc_lines.append(f"**Risk score:** {f.risk_score}")
            if f.attack_path:
                desc_lines.append("**Attack path:** " + " → ".join(f.attack_path[:5]))
            if f.description:
                desc_lines.append(f"**Detail:** {f.description[:600]}")
            desc = "\n".join(desc_lines)
        fields: list[dict[str, str]] = []
        ev = f.evidence
        if isinstance(ev, dict) and ev:
            snippet = json.dumps(ev, default=str)[:900]
            fields.append({"name": "Evidence (trimmed)", "value": f"```{snippet}```"})
        out = {
            "_title": title,
            "title": title[:256],
            "description": desc[:4090],
            "color": color,
        }
        if fields:
            out["fields"] = fields[:8]
        return out

    def _post(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                log.info("webhook delivered status=%s", resp.status)
        except urllib.error.URLError as e:
            log.error("webhook failed: %s", e)


def _parse_severity_str(s: str) -> Severity:
    try:
        return Severity(s.lower())
    except ValueError:
        return Severity.HIGH


@dataclass
class DiscordMultiChannelNotifier:
    """
    SOC-style routing to multiple Discord webhooks (URLs from `.env` via
    `DiscordWebhooksConfig`). Use `from_config()` after `load_config()` so dotenv is loaded.
    """

    webhooks: Any  # DiscordWebhooksConfig
    min_severity: Severity = Severity.HIGH
    deduplicate: bool = True
    alert_waf_detection: bool = True
    min_risk_score: float | None = None
    http_retries: int = 3
    http_timeout_seconds: float = 35.0
    staging_batch_max: int = 30
    attach_full_file_exports: bool = True
    broadcast_file_exports_all_channels: bool = False
    _seen: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set), repr=False
    )
    _embed_buffers: dict[str, list[dict[str, Any]]] = field(
        default_factory=lambda: defaultdict(list), repr=False
    )
    _webhook_warned: set[str] = field(default_factory=set, repr=False)

    @classmethod
    def from_config(cls, config: AppConfig) -> DiscordMultiChannelNotifier:
        return cls(
            webhooks=config.alerts.discord_webhooks,
            min_severity=_parse_severity_str(config.alerts.min_severity),
            deduplicate=config.alerts.deduplicate,
            alert_waf_detection=config.alerts.alert_waf_detection,
            min_risk_score=config.alerts.min_risk_score,
            http_retries=max(1, config.alerts.discord_http_retries),
            http_timeout_seconds=max(5.0, config.alerts.discord_http_timeout_seconds),
            staging_batch_max=max(5, config.alerts.discord_staging_batch_max),
            attach_full_file_exports=bool(config.alerts.discord_attach_full_file_exports),
            broadcast_file_exports_all_channels=bool(
                config.alerts.discord_broadcast_file_exports_all_channels
            ),
        )

    def _url(self, channel: str) -> str | None:
        u = self.webhooks.url_for(channel)
        if not u:
            if channel not in self._webhook_warned:
                self._webhook_warned.add(channel)
                log.warning(
                    "Discord webhook missing for channel %r — set DISCORD_WEBHOOK_%s in `.env`",
                    channel,
                    channel.upper(),
                )
            return None
        ul = u.lower()
        if not (
            ul.startswith("https://discord.com/api/webhooks/")
            or ul.startswith("https://discordapp.com/api/webhooks/")
        ):
            k = f"{channel}:badurl"
            if k not in self._webhook_warned:
                self._webhook_warned.add(k)
                log.warning("Channel %r URL is not a Discord webhook; skip", channel)
            return None
        return u

    def _dedupe(self, channel: str, key: str) -> bool:
        """Return True if we should skip (already sent)."""
        if not self.deduplicate:
            return False
        if key in self._seen[channel]:
            return True
        self._seen[channel].add(key)
        return False

    def _eligible_finding(self, f: Finding, channel: str) -> bool:
        """min_risk_score / min_severity apply to vuln-style alerts, not inventory channels."""
        if channel in (CH_SECRETS, CH_CRITICAL):
            return True
        if self.alert_waf_detection and f.vulnerability_type == "waf_detected":
            return True
        if channel == CH_STAGING:
            return True
        if channel in (CH_TECH, CH_PORTS):
            return True
        if self.min_risk_score is not None:
            if f.vulnerability_type != "waf_detected":
                if float(f.risk_score or 0.0) < self.min_risk_score:
                    return False
        return _SEVERITY_ORDER.get(f.severity, 0) >= _SEVERITY_ORDER.get(
            self.min_severity, 0
        )

    def _post_now(self, channel: str, payload: dict[str, Any]) -> None:
        url = self._url(channel)
        if not url:
            return
        run_discord_posts_sync(
            [(url, payload)],
            retries=self.http_retries,
            timeout_seconds=self.http_timeout_seconds,
        )

    def _buffer_embed(self, channel: str, embed: dict[str, Any]) -> None:
        self._embed_buffers[channel].append(embed)
        if len(self._embed_buffers[channel]) >= self.staging_batch_max:
            self.flush_channel(channel)

    def flush_channel(self, channel: str) -> None:
        embeds = self._embed_buffers.pop(channel, [])
        if not embeds:
            return
        url = self._url(channel)
        if not url:
            self._embed_buffers[channel].extend(embeds)
            return
        posts: list[tuple[str, dict[str, Any]]] = []
        label = channel.upper()
        for i in range(0, len(embeds), 10):
            chunk = embeds[i : i + 10]
            posts.append(
                (
                    url,
                    format_webhook_with_embeds(
                        f"[{label}] batched · {len(chunk)} item(s)", chunk
                    ),
                )
            )
        run_discord_posts_sync(
            posts,
            retries=self.http_retries,
            timeout_seconds=self.http_timeout_seconds,
        )

    def flush_all_buffers(self) -> None:
        for ch in list(self._embed_buffers.keys()):
            self.flush_channel(ch)

    def send_vulnerability(self, finding: Finding, run_id: str, domain: str) -> None:
        url = self._url(CH_VULNERABILITIES)
        if not url:
            return
        dk = f"{CH_VULNERABILITIES}:{finding.dedupe_key()}"
        if self._dedupe(CH_VULNERABILITIES, dk):
            return
        if not self._eligible_finding(finding, CH_VULNERABILITIES):
            return
        emb = format_finding_embed(finding, run_id, domain)
        pl = format_webhook_with_embeds(
            f"[VULN] `{finding.target}` · `{finding.vulnerability_type}`",
            [emb],
        )
        self._post_now(CH_VULNERABILITIES, pl)

    def send_tech_profile(
        self,
        asset: Asset | None,
        run_id: str,
        domain: str,
        *,
        finding: Finding | None = None,
    ) -> None:
        if finding is None and asset is None:
            return
        url = self._url(CH_TECH)
        if not url:
            return
        key = (
            f"{CH_TECH}:{finding.discord_notify_dedupe_key(CH_TECH)}"
            if finding
            else f"{CH_TECH}:asset:{asset.stable_id() if asset else 'none'}"
        )
        if self._dedupe(CH_TECH, key):
            return
        pl = format_tech_profile_payload(
            asset=asset, finding=finding, run_id=run_id, domain=domain
        )
        if finding and finding_immediate_delivery(finding):
            self._post_now(CH_TECH, pl)
        elif not finding and asset is not None:
            self._post_now(CH_TECH, pl)
        else:
            e = pl.get("embeds") or []
            if e:
                self._buffer_embed(CH_TECH, e[0])

    def send_ports(self, finding: Finding, run_id: str, domain: str) -> None:
        """Port / service observations (naabu, nmap)."""
        url = self._url(CH_PORTS)
        if not url:
            return
        dk = f"{CH_PORTS}:{finding.dedupe_key()}"
        if self._dedupe(CH_PORTS, dk):
            return
        pl = format_ports_payload(finding, run_id, domain)
        if finding_immediate_delivery(finding):
            self._post_now(CH_PORTS, pl)
        else:
            e = pl.get("embeds") or []
            if e:
                self._buffer_embed(CH_PORTS, e[0])

    def send_surface_inventory(
        self,
        inventory: dict[str, Any],
        run_id: str,
        domain: str,
    ) -> None:
        """Post deduplicated hosts / URLs / paths after enumeration + URL harvest."""
        targets: tuple[str, ...] = (
            ALL_DISCORD_CHANNEL_KEYS
            if self.attach_full_file_exports and self.broadcast_file_exports_all_channels
            else (CH_ASSETS,)
        )
        for ch in targets:
            url = self._url(ch)
            if not url:
                continue
            dk = f"{ch}:surface_inv:{run_id}"
            if self._dedupe(ch, dk):
                continue
            if self.attach_full_file_exports:
                pl = format_surface_inventory_summary_payload(
                    inventory,
                    run_id,
                    domain,
                    channel_label=ch.upper(),
                )
                files = build_inventory_export_files(inventory, domain, run_id)
                for job in multipart_jobs_for_webhook(url, pl, files):
                    run_discord_multipart_posts_sync(
                        [job],
                        retries=self.http_retries,
                        timeout_seconds=self.http_timeout_seconds,
                    )
            else:
                if ch != CH_ASSETS:
                    continue
                pl = format_surface_inventory_payload(inventory, run_id, domain)
                self._post_now(CH_ASSETS, pl)

    def send_full_run_file_exports(
        self,
        findings: list[Finding],
        assets: list[Asset],
        run_id: str,
        domain: str,
    ) -> None:
        """
        After scanning: attach complete findings (jsonl), asset list, run summary.
        Respects attach_full_file_exports and broadcast_file_exports_all_channels.
        """
        if not self.attach_full_file_exports:
            return
        if self.broadcast_file_exports_all_channels:
            targets = ALL_DISCORD_CHANNEL_KEYS
        elif self._url(CH_SUMMARY):
            targets = (CH_SUMMARY,)
        elif self._url(CH_ASSETS):
            targets = (CH_ASSETS,)
        else:
            return
        files = build_final_scan_export_files(findings, assets, run_id, domain)
        for ch in targets:
            url = self._url(ch)
            if not url:
                continue
            dk = f"{ch}:final_export:{run_id}"
            if self._dedupe(ch, dk):
                continue
            pl = format_webhook_with_embeds(
                f"[{ch.upper()}] **Full run export** · `{domain}` · `{run_id}`",
                [
                    {
                        "title": "Findings & assets (attachments)",
                        "description": (
                            f"**Findings:** `{len(findings)}` · **Assets:** `{len(assets)}`\n\n"
                            "_Attached: `findings.jsonl`, `assets.txt`, `run_summary.json`._"
                        )[:4090],
                        "color": 0x2ECC71,
                    }
                ],
            )
            for job in multipart_jobs_for_webhook(url, pl, files):
                run_discord_multipart_posts_sync(
                    [job],
                    retries=self.http_retries,
                    timeout_seconds=self.http_timeout_seconds,
                )

    def send_asset_discovery(self, assets: list[Asset], run_id: str, domain: str) -> None:
        url = self._url(CH_ASSETS)
        if not url:
            return
        dk = f"{CH_ASSETS}:discovery:{run_id}"
        if self._dedupe(CH_ASSETS, dk):
            return
        payloads = format_asset_discovery_payloads(assets, run_id, domain)
        run_discord_posts_sync(
            [(url, pl) for pl in payloads],
            retries=self.http_retries,
            timeout_seconds=self.http_timeout_seconds,
        )

    def send_critical_subdomain(self, asset: Asset, run_id: str, domain: str) -> None:
        url = self._url(CH_CRITICAL)
        if not url:
            return
        dk = f"{CH_CRITICAL}:{asset.stable_id()}:{run_id}"
        if self._dedupe(CH_CRITICAL, dk):
            return
        pl = format_critical_subdomain_payload(asset, run_id, domain)
        self._post_now(CH_CRITICAL, pl)

    def send_secret(self, finding: Finding, run_id: str, domain: str) -> None:
        url = self._url(CH_SECRETS)
        if not url:
            return
        dk = f"{CH_SECRETS}:{finding.dedupe_key()}"
        if self._dedupe(CH_SECRETS, dk):
            return
        emb = format_finding_embed(finding, run_id, domain)
        emb["title"] = "Secret / sensitive pattern"
        pl = format_webhook_with_embeds(
            f"[SECRET] `{finding.target}` · `{finding.vulnerability_type}`",
            [emb],
        )
        self._post_now(CH_SECRETS, pl)

    def send_staging(self, asset: Asset, run_id: str, domain: str) -> None:
        """Single asset staging signal (prefer `send_staging_batch` for analysis)."""
        self.send_staging_batch([asset], run_id, domain)

    def send_staging_batch(self, assets: list[Asset], run_id: str, domain: str) -> None:
        url = self._url(CH_STAGING)
        if not url or not assets:
            return
        dk = f"{CH_STAGING}:batch:{run_id}"
        if self._dedupe(CH_STAGING, dk):
            return
        pl = format_staging_asset_payload(assets, run_id, domain)
        self._post_now(CH_STAGING, pl)

    def send_summary(
        self,
        report: dict[str, Any],
        run_id: str,
        domain: str,
        *,
        total_assets: int,
        findings: list[Finding],
    ) -> None:
        """Pipeline summary embed → dedicated `DISCORD_WEBHOOK_SUMMARY` channel."""
        if not self._url(CH_SUMMARY):
            return
        dk = f"{CH_SUMMARY}:pipeline_summary:{run_id}"
        if self._dedupe(CH_SUMMARY, dk):
            return
        pl = format_summary_payload(
            report,
            run_id,
            domain,
            total_assets=total_assets,
            findings=findings,
        )
        self._post_now(CH_SUMMARY, pl)

    def ingest_scan_finding(self, finding: Finding, run_id: str, domain: str) -> None:
        """
        Route a scanner finding to the correct channel with immediate vs batched policy.
        """
        ch = route_finding_channel(finding)
        if not self._eligible_finding(finding, ch):
            return
        dk = f"{ch}:{finding.discord_notify_dedupe_key(ch)}"
        if self._dedupe(ch, dk):
            return
        emb = format_finding_embed(finding, run_id, domain)
        tag = ch.upper()
        pl = format_webhook_with_embeds(f"[{tag}] `{finding.target}`", [emb])
        immediate = finding_immediate_delivery(finding)
        if ch == CH_SECRETS:
            self._post_now(CH_SECRETS, pl)
            return
        if ch == CH_CRITICAL:
            self._post_now(CH_CRITICAL, pl)
            return
        if finding.vulnerability_type == "waf_detected":
            self._post_now(CH_VULNERABILITIES, pl)
            return
        if immediate:
            u = self._url(ch)
            if u:
                run_discord_posts_sync(
                    [(u, pl)],
                    retries=self.http_retries,
                    timeout_seconds=self.http_timeout_seconds,
                )
            return
        self._buffer_embed(ch, emb)

    def process_scan_findings(
        self, findings: list[Finding], run_id: str, domain: str
    ) -> None:
        for f in findings:
            self.ingest_scan_finding(f, run_id, domain)


def use_discord_multi_channel(config: AppConfig) -> bool:
    return bool(
        config.alerts.discord_use_env_webhooks
        and config.alerts.discord_webhooks.any_configured()
    )
