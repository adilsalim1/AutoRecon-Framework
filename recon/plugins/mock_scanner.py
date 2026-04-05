from __future__ import annotations

from typing import Any

from recon.models.assets import Asset
from recon.models.findings import Finding, Severity
from recon.plugins.base import RawScanResult, ScanContext, ScannerPlugin


class MockVulnerabilityScanner(ScannerPlugin):
    """
    Deterministic mock scanner for pipeline validation.
    Replace with real integrations under plugins/ (e.g. nuclei, custom API).
    """

    name = "mock_scanner"
    version = "1.0.0"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        findings_data: list[dict[str, Any]] = []
        for a in targets:
            seed = sum(ord(c) for c in a.identifier) % 5
            if seed == 0:
                findings_data.append(
                    {
                        "host": a.identifier,
                        "check": "exposed_debug_endpoint",
                        "severity": "high",
                        "detail": {"path": "/.debug", "status": 200},
                    }
                )
            elif seed == 1:
                findings_data.append(
                    {
                        "host": a.identifier,
                        "check": "tls_cert_expiring",
                        "severity": "medium",
                        "detail": {"days_left": 14},
                    }
                )
            elif seed == 2:
                findings_data.append(
                    {
                        "host": a.identifier,
                        "check": "missing_security_header",
                        "severity": "low",
                        "detail": {"header": "Strict-Transport-Security"},
                    }
                )
        return RawScanResult(
            scanner_name=self.name,
            targets=[t.identifier for t in targets],
            raw_payload={"mock_findings": findings_data},
            success=True,
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        out: list[Finding] = []
        for item in raw.raw_payload.get("mock_findings", []):
            sev = Severity(item.get("severity", "info"))
            out.append(
                Finding(
                    target=item["host"],
                    vulnerability_type=item.get("check", "unknown"),
                    severity=sev,
                    evidence=dict(item.get("detail", {})),
                    source_scanner=raw.scanner_name,
                    title=item.get("check", "finding"),
                    description="Synthetic finding from mock scanner",
                )
            )
        return out

    def normalize(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            if not f.source_scanner:
                f.source_scanner = self.name
        return findings
