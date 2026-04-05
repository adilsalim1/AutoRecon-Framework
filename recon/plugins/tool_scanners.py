from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from recon.core.logger import get_logger
from recon.models.assets import Asset
from recon.models.findings import Finding, Severity
from recon.plugins.base import RawScanResult, ScanContext, ScannerPlugin
from recon.utils.tool_runner import resolve_binary, run_tool

log = get_logger("tool_scanners")


def _timeout(ctx: ScanContext, default: int = 300) -> int:
    return int(ctx.metadata.get("scan_timeout_seconds", default))


def _map_nuclei_severity(s: str) -> Severity:
    s = (s or "info").lower()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "unknown": Severity.INFO,
    }.get(s, Severity.MEDIUM)


class HttpxScannerPlugin(ScannerPlugin):
    """Probe live HTTP(S) services; emits informational findings with tech/title."""

    name = "httpx_scanner"
    version = "1.0.0"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"lines": []})
        host = targets[0].identifier.strip()
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "httpx", "httpx")
        lines: list[str] = []
        err = ""
        last_rc = 0
        for scheme in ("https", "http"):
            proc = run_tool(
                [bin_path, "-u", f"{scheme}://{host}", "-silent", "-json", "-timeout", "10"],
                timeout=_timeout(ctx=context, default=120),
            )
            last_rc = proc.returncode
            err = proc.stderr or err
            if proc.stdout.strip():
                lines.extend(proc.stdout.strip().splitlines())
                break
        if not lines and last_rc != 0:
            return RawScanResult(
                scanner_name=self.name,
                targets=[host],
                success=False,
                error_message=(err or f"httpx exit {last_rc}")[:2000],
                raw_payload={"lines": []},
            )
        return RawScanResult(
            scanner_name=self.name,
            targets=[host],
            success=True,
            raw_payload={"lines": lines},
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        out: list[Finding] = []
        for line in raw.raw_payload.get("lines", []):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = row.get("url") or row.get("input", "")
            out.append(
                Finding(
                    target=url or (raw.targets[0] if raw.targets else ""),
                    vulnerability_type="live_http_service",
                    severity=Severity.INFO,
                    evidence={
                        "status_code": row.get("status_code"),
                        "title": row.get("title"),
                        "technologies": row.get("tech", row.get("technologies")),
                        "server": row.get("server"),
                    },
                    source_scanner=self.name,
                    title="HTTP(S) probe",
                )
            )
        return out


class NucleiScannerPlugin(ScannerPlugin):
    """Template-based scanner; expects nuclei with -jsonl."""

    name = "nuclei_scanner"
    version = "1.0.0"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"lines": []})
        host = targets[0].identifier.strip()
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "nuclei", "nuclei")
        lines: list[str] = []
        err_all = ""
        for scheme in ("https", "http"):
            proc = run_tool(
                [
                    bin_path,
                    "-u",
                    f"{scheme}://{host}",
                    "-jsonl",
                    "-silent",
                    "-nc",
                    "-timeout",
                    "15",
                ],
                timeout=_timeout(ctx=context, default=600),
            )
            err_all = proc.stderr or err_all
            if proc.stdout.strip():
                lines.extend(proc.stdout.strip().splitlines())
                break
        return RawScanResult(
            scanner_name=self.name,
            targets=[host],
            success=True,
            raw_payload={"lines": lines, "stderr": err_all},
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        out: list[Finding] = []
        for line in raw.raw_payload.get("lines", []):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = row.get("info") or {}
            sev = _map_nuclei_severity(str(info.get("severity", "info")))
            matched = row.get("matched-at") or row.get("host", "")
            out.append(
                Finding(
                    target=str(matched),
                    vulnerability_type=str(row.get("template-id", "nuclei_finding")),
                    severity=sev,
                    evidence={
                        "matcher": row.get("matcher-name"),
                        "type": row.get("type"),
                        "name": info.get("name"),
                        "reference": info.get("reference"),
                    },
                    source_scanner=self.name,
                    title=str(info.get("name", row.get("template-id", "finding"))),
                    description=str(info.get("description", "")),
                )
            )
        return out


class SubjackScannerPlugin(ScannerPlugin):
    name = "subjack_scanner"
    version = "1.0.0"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"stdout": ""})
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "subjack", "subjack")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            for t in targets:
                f.write(t.identifier.strip() + "\n")
            path = f.name
        try:
            proc = run_tool(
                [bin_path, "-w", path, "-ssl", "-t", "20", "-timeout", "15"],
                timeout=_timeout(ctx=context, default=300),
            )
        finally:
            Path(path).unlink(missing_ok=True)
        return RawScanResult(
            scanner_name=self.name,
            targets=[t.identifier for t in targets],
            success=True,
            raw_payload={"stdout": proc.stdout, "stderr": proc.stderr},
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        text = raw.raw_payload.get("stdout", "") + raw.raw_payload.get("stderr", "")
        out: list[Finding] = []
        if re.search(r"(?i)vulnerable|takeover", text) and "not vulnerable" not in text.lower():
            for t in raw.targets:
                out.append(
                    Finding(
                        target=t,
                        vulnerability_type="subdomain_takeover_candidate",
                        severity=Severity.HIGH,
                        evidence={"snippet": text.strip()[:2000]},
                        source_scanner=self.name,
                        title="Subjack reported possible takeover",
                    )
                )
        return out


class SubzyScannerPlugin(ScannerPlugin):
    name = "subzy_scanner"
    version = "1.0.0"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"stdout": ""})
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "subzy", "subzy")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            for t in targets:
                f.write(t.identifier.strip() + "\n")
            path = f.name
        try:
            proc = run_tool(
                [bin_path, "--targets", path],
                timeout=_timeout(ctx=context, default=300),
            )
        finally:
            Path(path).unlink(missing_ok=True)
        return RawScanResult(
            scanner_name=self.name,
            targets=[t.identifier for t in targets],
            success=True,
            raw_payload={"stdout": proc.stdout, "stderr": proc.stderr},
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        text = raw.raw_payload.get("stdout", "") + raw.raw_payload.get("stderr", "")
        out: list[Finding] = []
        if re.search(r"(?i)vulnerable|takeover", text):
            for t in raw.targets:
                out.append(
                    Finding(
                        target=t,
                        vulnerability_type="subdomain_takeover_candidate",
                        severity=Severity.HIGH,
                        evidence={"snippet": text.strip()[:2000]},
                        source_scanner=self.name,
                        title="Subzy reported possible takeover",
                    )
                )
        return out


class Wafw00fScannerPlugin(ScannerPlugin):
    """
    WAF fingerprinting via wafw00f (https://github.com/EnableSecurity/wafw00f).
    Install: pip install wafw00f — then use `wafw00f` on PATH or set tools.wafw00f.
    """

    name = "wafw00f_scanner"
    version = "1.0.0"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={})
        host = targets[0].identifier.strip()
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "wafw00f", "wafw00f")
        aggressive = bool(context.metadata.get("wafw00f_aggressive"))
        timeout = max(60, _timeout(ctx=context, default=180))
        last_out = ""
        last_err = ""
        last_rc = 0
        tested_url = ""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            argv = [bin_path, url]
            if aggressive:
                argv.append("-a")
            proc = run_tool(argv, timeout=timeout)
            last_out = proc.stdout or ""
            last_err = proc.stderr or ""
            last_rc = proc.returncode
            tested_url = url
            if last_out.strip() or last_err.strip():
                break
        success = last_rc == 0 or bool(last_out.strip() or last_err.strip())
        if not success and last_rc != 0:
            return RawScanResult(
                scanner_name=self.name,
                targets=[host],
                success=False,
                error_message=(last_err or f"wafw00f exit {last_rc}")[:2000],
                raw_payload={
                    "stdout": last_out,
                    "stderr": last_err,
                    "url": tested_url,
                },
            )
        return RawScanResult(
            scanner_name=self.name,
            targets=[host],
            success=True,
            raw_payload={
                "stdout": last_out,
                "stderr": last_err,
                "url": tested_url,
            },
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        text = (raw.raw_payload.get("stdout", "") + "\n" + raw.raw_payload.get("stderr", "")).strip()
        target = str(raw.raw_payload.get("url") or (raw.targets[0] if raw.targets else ""))
        out: list[Finding] = []
        if not text:
            return out
        tl = text.lower()
        positive_lines = [
            ln.strip()
            for ln in text.splitlines()
            if "[+]" in ln
            and ("behind" in ln.lower() or "waf" in ln.lower() or "detected" in ln.lower())
        ]
        if positive_lines or (
            "is behind" in tl and "waf" in tl
        ) or re.search(r"(?i)number of wafs?\s+detected\s*:\s*[1-9]", text):
            vendor_guess = ""
            for ln in positive_lines:
                m = re.search(r"(?i)is behind\s+(.+?)(?:\s+waf\.?$|\.$)", ln)
                if m:
                    vendor_guess = m.group(1).strip()
                    break
            if not vendor_guess and positive_lines:
                vendor_guess = positive_lines[0][:500]
            out.append(
                Finding(
                    target=target,
                    vulnerability_type="waf_detected",
                    severity=Severity.INFO,
                    evidence={
                        "vendor_hint": vendor_guess,
                        "lines": positive_lines[:15],
                        "full_output": text[:8000],
                    },
                    source_scanner=self.name,
                    title="WAF detected (wafw00f)",
                    description="Target appears to sit behind a WAF; review wafw00f output for vendor/fingerprint.",
                )
            )
            return out
        if re.search(r"(?i)no waf detected|not behind any waf", tl):
            out.append(
                Finding(
                    target=target,
                    vulnerability_type="waf_not_detected",
                    severity=Severity.INFO,
                    evidence={"output": text[:4000]},
                    source_scanner=self.name,
                    title="No WAF detected (wafw00f)",
                )
            )
            return out
        out.append(
            Finding(
                target=target,
                vulnerability_type="waf_detection_inconclusive",
                severity=Severity.INFO,
                evidence={"output": text[:6000]},
                source_scanner=self.name,
                title="WAF check inconclusive (wafw00f)",
                description="Could not classify wafw00f output; inspect raw evidence.",
            )
        )
        return out


class FfufScannerPlugin(ScannerPlugin):
    """Directory/parameter fuzzing — requires scanning.ffuf_wordlist in config."""

    name = "ffuf_scanner"
    version = "1.0.0"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        wl = str(context.metadata.get("ffuf_wordlist", "") or "").strip()
        if not wl or not Path(wl).is_file():
            return RawScanResult(
                scanner_name=self.name,
                success=False,
                error_message="Set scanning.ffuf_wordlist to a valid wordlist file path.",
                raw_payload={},
            )
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"lines": []})
        host = targets[0].identifier.strip()
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "ffuf", "ffuf")
        url = f"https://{host}/FUZZ"
        proc = run_tool(
            [
                bin_path,
                "-u",
                url,
                "-w",
                wl,
                "-json",
                "-s",
                "-t",
                "20",
                "-timeout",
                "10",
            ],
            timeout=_timeout(ctx=context, default=600),
        )
        return RawScanResult(
            scanner_name=self.name,
            targets=[host],
            success=proc.returncode == 0 or bool(proc.stdout.strip()),
            raw_payload={"stdout": proc.stdout, "stderr": proc.stderr},
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        out: list[Finding] = []
        for line in raw.raw_payload.get("stdout", "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("type") != "result":
                continue
            inp = (row.get("input") or {}).get("FUZZ", "")
            url = row.get("url", "")
            sc = row.get("status")
            if sc in (200, 301, 302, 401, 403) and inp:
                out.append(
                    Finding(
                        target=url,
                        vulnerability_type="ffuf_hit",
                        severity=Severity.INFO,
                        evidence={"status": sc, "length": row.get("length")},
                        source_scanner=self.name,
                        title=f"FFUF match ({sc})",
                    )
                )
        return out


class SecretFinderScannerPlugin(ScannerPlugin):
    """Runs SecretFinder against one origin — set scanning.secretfinder_script (Python script path)."""

    name = "secretfinder_scanner"
    version = "1.0.0"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        script = str(context.metadata.get("secretfinder_script", "") or "").strip()
        py = resolve_binary(context.metadata.get("tool_paths") or {}, "python3", "python3")
        if not script or not Path(script).is_file():
            return RawScanResult(
                scanner_name=self.name,
                success=False,
                error_message="Set scanning.secretfinder_script to SecretFinder.py path.",
                raw_payload={},
            )
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"stdout": ""})
        host = targets[0].identifier.strip()
        url = f"https://{host}"
        proc = run_tool(
            [py, script, "-i", url, "-o", "cli"],
            timeout=_timeout(ctx=context, default=300),
        )
        return RawScanResult(
            scanner_name=self.name,
            targets=[host],
            success=True,
            raw_payload={"stdout": proc.stdout, "stderr": proc.stderr},
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        text = raw.raw_payload.get("stdout", "")
        out: list[Finding] = []
        if not text.strip():
            return out
        for t in raw.targets:
            out.append(
                Finding(
                    target=t,
                    vulnerability_type="secret_candidate",
                    severity=Severity.MEDIUM,
                    evidence={"output": text.strip()[:8000]},
                    source_scanner=self.name,
                    title="SecretFinder output (manual review)",
                )
            )
        return out
