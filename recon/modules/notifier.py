from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from recon.core.logger import get_logger
from recon.models.findings import Finding, Severity

log = get_logger("notifier")

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class WebhookNotifier:
    webhook_url: str
    min_severity: Severity = Severity.HIGH
    batch_summaries: bool = True
    deduplicate: bool = True
    _sent_keys: set[str] = field(default_factory=set, repr=False)

    def _meets_threshold(self, f: Finding) -> bool:
        return _SEVERITY_ORDER.get(f.severity, 0) >= _SEVERITY_ORDER.get(self.min_severity, 0)

    def notify(self, findings: list[Finding], run_id: str, domain: str) -> None:
        if not self.webhook_url:
            log.info("webhook not configured; skipping alerts")
            return
        candidates = [f for f in findings if self._meets_threshold(f)]
        if self.deduplicate:
            fresh: list[Finding] = []
            for f in candidates:
                k = f.dedupe_key()
                if k in self._sent_keys:
                    continue
                self._sent_keys.add(k)
                fresh.append(f)
            candidates = fresh
        if not candidates:
            return
        if self.batch_summaries:
            payload = self._batch_payload(run_id, domain, candidates)
            self._post(payload)
        else:
            for f in candidates:
                self._post(self._single_payload(run_id, domain, f))

    def _single_payload(self, run_id: str, domain: str, f: Finding) -> dict[str, Any]:
        return {
            "event": "recon.finding",
            "run_id": run_id,
            "domain": domain,
            "finding": f.to_dict(),
        }

    def _batch_payload(self, run_id: str, domain: str, findings: list[Finding]) -> dict[str, Any]:
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        return {
            "event": "recon.batch",
            "run_id": run_id,
            "domain": domain,
            "count": len(findings),
            "by_severity": by_sev,
            "findings": [f.to_dict() for f in findings],
        }

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
