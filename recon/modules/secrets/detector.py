from __future__ import annotations

from recon.models.findings import Finding, Severity
from recon.modules.secrets.patterns import BUILTIN_PATTERNS, SecretPattern


class SecretDetector:
    """Apply configured regex patterns to arbitrary text (URLs, JS snippets, bodies)."""

    def __init__(self, patterns: tuple[SecretPattern, ...] | None = None) -> None:
        self._patterns = patterns if patterns is not None else BUILTIN_PATTERNS

    def scan_text(
        self,
        text: str,
        *,
        source_ref: str,
        source_scanner: str = "secret_detector",
    ) -> list[Finding]:
        if not text or len(text) > 2_000_000:
            return []
        findings: list[Finding] = []
        for sp in self._patterns:
            for m in sp.pattern.finditer(text):
                raw = m.group(0)
                if sp.name == "api_key_assignment" and m.lastindex:
                    raw = m.group(1) or raw
                if sp.name == "oauth_client_secret" and m.lastindex:
                    raw = m.group(1) or raw
                snippet = raw[:200] + ("…" if len(raw) > 200 else "")
                findings.append(
                    Finding(
                        target=source_ref,
                        vulnerability_type=f"secret_{sp.name}",
                        severity=sp.severity,
                        evidence={
                            "pattern": sp.name,
                            "snippet_redacted": snippet[:80] + "…",
                            "match_len": len(raw),
                        },
                        source_scanner=source_scanner,
                        title=f"Possible {sp.name.replace('_', ' ')}",
                        description="Regex match; verify manually (high false-positive rate).",
                        source_ref=source_ref,
                        confidence=sp.confidence,
                        exploitability="unknown",
                    )
                )
        return findings

    def scan_urls(
        self,
        urls: list[str],
        *,
        source_scanner: str = "secret_detector",
        max_urls: int = 500,
    ) -> list[Finding]:
        out: list[Finding] = []
        for u in urls[:max_urls]:
            out.extend(
                self.scan_text(u, source_ref=u, source_scanner=source_scanner)
            )
        return out


def merge_secret_severity(a: Severity, b: Severity) -> Severity:
    order = (
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    )
    ia = order.index(a) if a in order else 0
    ib = order.index(b) if b in order else 0
    return order[max(ia, ib)]
