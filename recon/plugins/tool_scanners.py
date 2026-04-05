from __future__ import annotations

import ipaddress
import json
import re
import socket
import tempfile
from pathlib import Path

from recon.core.logger import get_logger
from recon.models.assets import Asset
from recon.models.findings import Finding, Severity
from recon.plugins.base import RawScanResult, ScanContext, ScannerPlugin
from recon.utils.tool_runner import resolve_binary, resolve_httpx_binary, run_tool

log = get_logger("tool_scanners")


def _timeout(ctx: ScanContext, default: int = 300) -> int:
    return int(ctx.metadata.get("scan_timeout_seconds", default))


def _run_tool_ctx(
    ctx: ScanContext,
    argv: list[str],
    timeout: int,
    tool_label: str,
    *,
    stdin_text: str | None = None,
):
    """Run external binary; stream lines to stderr when stream_subprocess_output is true."""
    return run_tool(
        argv,
        timeout=timeout,
        stdin_text=stdin_text,
        live_output=bool(ctx.metadata.get("stream_subprocess_output", True)),
        live_prefix=tool_label,
    )


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
        bin_path = resolve_httpx_binary(context.metadata.get("tool_paths") or {})
        lines: list[str] = []
        err = ""
        last_rc = 0
        # ProjectDiscovery httpx: one URL per line on stdin (pipe-friendly; see PD httpx README).
        argv = [bin_path, "-silent", "-json", "-timeout", "10"]
        for scheme in ("https", "http"):
            proc = _run_tool_ctx(
                context,
                argv,
                timeout=_timeout(ctx=context, default=120),
                tool_label="httpx",
                stdin_text=f"{scheme}://{host}\n",
            )
            last_rc = proc.returncode
            err = proc.stderr or err
            if proc.stdout.strip():
                lines.extend(proc.stdout.strip().splitlines())
                break
        if not lines and last_rc != 0:
            hint = ""
            low = (err or "").lower()
            if "no such option" in low or "usage: httpx [options] url" in low:
                hint = (
                    " You likely have Encode/python httpx on PATH instead of ProjectDiscovery httpx; "
                    'set tools.httpx to "$(go env GOPATH)/bin/httpx" or run --install-tools.'
                )
            return RawScanResult(
                scanner_name=self.name,
                targets=[host],
                success=False,
                error_message=((err or f"httpx exit {last_rc}") + hint)[:2000],
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
    scan_tier = "aggressive"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"lines": []})
        host = targets[0].identifier.strip()
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "nuclei", "nuclei")
        lines: list[str] = []
        err_all = ""
        for scheme in ("https", "http"):
            proc = _run_tool_ctx(
                context,
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
                tool_label="nuclei",
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
    scan_tier = "aggressive"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"stdout": ""})
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "subjack", "subjack")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            for t in targets:
                f.write(t.identifier.strip() + "\n")
            path = f.name
        try:
            proc = _run_tool_ctx(
                context,
                [bin_path, "-w", path, "-ssl", "-t", "20", "-timeout", "15"],
                timeout=_timeout(ctx=context, default=300),
                tool_label="subjack",
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
    scan_tier = "aggressive"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"stdout": ""})
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "subzy", "subzy")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            for t in targets:
                f.write(t.identifier.strip() + "\n")
            path = f.name
        try:
            proc = _run_tool_ctx(
                context,
                [bin_path, "--targets", path],
                timeout=_timeout(ctx=context, default=300),
                tool_label="subzy",
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


def _wafw00f_register_pipeline(context: ScanContext, host: str, stdout: str, stderr: str) -> None:
    """Record WAF vendor in shared pipeline_runtime for downstream aggressive-scan gating."""
    text = (stdout + "\n" + stderr).strip()
    if not text:
        return
    tl = text.lower()
    positive_lines = [
        ln.strip()
        for ln in text.splitlines()
        if "[+]" in ln
        and ("behind" in ln.lower() or "waf" in ln.lower() or "detected" in ln.lower())
    ]
    detected = bool(
        positive_lines
        or ("is behind" in tl and "waf" in tl)
        or re.search(r"(?i)number of wafs?\s+detected\s*:\s*[1-9]", text)
    )
    if not detected:
        return
    vendor_guess = ""
    for ln in positive_lines:
        m = re.search(r"(?i)is behind\s+(.+?)(?:\s+waf\.?$|\.$)", ln)
        if m:
            vendor_guess = m.group(1).strip()
            break
    if not vendor_guess and positive_lines:
        vendor_guess = positive_lines[0][:500]
    pr = context.metadata.get("pipeline_runtime")
    if not isinstance(pr, dict):
        return
    wmap = pr.setdefault("waf_by_host", {})
    key = host.lower().strip().rstrip(".")
    wmap[key] = vendor_guess or "unknown"


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
            proc = _run_tool_ctx(context, argv, timeout=timeout, tool_label="wafw00f")
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
        _wafw00f_register_pipeline(context, host, last_out, last_err)
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
                    severity=Severity.MEDIUM,
                    evidence={
                        "waf_vendor": vendor_guess or "unknown",
                        "vendor_hint": vendor_guess,
                        "lines": positive_lines[:15],
                        "full_output": text[:8000],
                    },
                    source_scanner=self.name,
                    title="WAF detected (wafw00f)",
                    description="Target sits behind a WAF; aggressive scanners are skipped for this host when waf_skip_aggressive is enabled.",
                    source_ref=target,
                    confidence=0.85 if vendor_guess else 0.6,
                    exploitability="blocked_layer",
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


def _parse_nmap_grepable_line(line: str) -> list[dict[str, str]]:
    """Parse `Ports:` segment from nmap -oG (grepable) output."""
    if "Ports:" not in line or "Host:" not in line:
        return []
    host_m = re.search(r"Host:\s*(\S+)", line)
    host = host_m.group(1) if host_m else ""
    pm = re.search(r"Ports:\s*([^I]+?)(?:\s+Ignored|\s*$)", line)
    if not pm:
        return []
    blob = pm.group(1).strip()
    out: list[dict[str, str]] = []
    for part in blob.split(","):
        part = part.strip().rstrip("/")
        if not part or part == "Not shown":
            continue
        fields = part.split("/")
        if len(fields) < 3:
            continue
        port, state, proto = fields[0], fields[1], fields[2]
        if state != "open":
            continue
        service = fields[4] if len(fields) > 4 else ""
        version = "/".join(fields[5:]).strip("/") if len(fields) > 5 else ""
        out.append(
            {
                "host": host,
                "port": port,
                "protocol": proto,
                "service": service,
                "version": version,
            }
        )
    return out


def _severity_for_exposed_service(service: str, version: str) -> Severity:
    s = (service or "").lower()
    if s in ("telnet", "rsh", "rexec"):
        return Severity.MEDIUM
    if s == "ftp" and "anonymous" in (version or "").lower():
        return Severity.MEDIUM
    return Severity.INFO


class NaabuScannerPlugin(ScannerPlugin):
    """
    Fast TCP port discovery via ProjectDiscovery naabu (`-host`, `-top-ports`, `-json`).
    See https://docs.projectdiscovery.io/tools/naabu/running — use only where you are authorized to port-scan.
    """

    name = "naabu_scanner"
    version = "1.0.0"
    scan_tier = "aggressive"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"stdout": ""})
        host = targets[0].identifier.strip()
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "naabu", "naabu")
        top = max(1, min(65535, int(context.metadata.get("naabu_top_ports", 100))))
        proc = _run_tool_ctx(
            context,
            [
                bin_path,
                "-host",
                host,
                "-silent",
                "-json",
                "-top-ports",
                str(top),
            ],
            timeout=_timeout(ctx=context, default=600),
            tool_label="naabu",
        )
        ok = proc.returncode == 0 or bool(proc.stdout.strip())
        return RawScanResult(
            scanner_name=self.name,
            targets=[host],
            success=ok,
            raw_payload={"stdout": proc.stdout, "stderr": proc.stderr},
            error_message=None
            if ok
            else (proc.stderr or f"naabu exit {proc.returncode}")[:2000],
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        out: list[Finding] = []
        host = raw.targets[0] if raw.targets else ""
        for line in raw.raw_payload.get("stdout", "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            port = row.get("port")
            if port is None:
                continue
            ip = str(row.get("ip") or row.get("host") or host)
            target = f"{ip}:{port}"
            out.append(
                Finding(
                    target=target,
                    vulnerability_type="open_tcp_port",
                    severity=Severity.INFO,
                    evidence={"ip": ip, "port": port, "scanner_asset": host},
                    source_scanner=self.name,
                    title=f"Open TCP port {port} ({ip})",
                    description="Naabu reported an open port. Follow with nmap_scanner (-sV) or nuclei network templates for service/CVE checks.",
                )
            )
        return out


class NmapScannerPlugin(ScannerPlugin):
    """
    Service/version detection: `nmap -Pn -sV --top-ports=N -oG - <host>`.
    Optional `scanning.nmap_scripts` adds `--script=...` (e.g. vuln category where allowed).
    Parsed grepable output → exposed_service findings for CVE correlation / nuclei.
    """

    name = "nmap_scanner"
    version = "1.0.0"
    scan_tier = "aggressive"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"stdout": ""})
        host = targets[0].identifier.strip()
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "nmap", "nmap")
        top = max(1, min(65535, int(context.metadata.get("nmap_top_ports", 50))))
        timeout = int(context.metadata.get("nmap_scan_timeout_seconds", 900))
        scripts = str(context.metadata.get("nmap_scripts", "") or "").strip()
        argv = [bin_path, "-Pn", "-sV", f"--top-ports={top}", "-oG", "-", host]
        if scripts:
            argv.insert(1, f"--script={scripts}")
        proc = _run_tool_ctx(
            context,
            argv,
            timeout=timeout,
            tool_label="nmap",
        )
        text = proc.stdout or ""
        ok = proc.returncode == 0 or "Host:" in text or "Ports:" in text
        return RawScanResult(
            scanner_name=self.name,
            targets=[host],
            success=ok,
            raw_payload={"stdout": text, "stderr": proc.stderr},
            error_message=None
            if ok
            else (proc.stderr or f"nmap exit {proc.returncode}")[:2000],
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        out: list[Finding] = []
        host = raw.targets[0] if raw.targets else ""
        seen: set[tuple[str, str]] = set()
        for line in raw.raw_payload.get("stdout", "").splitlines():
            for row in _parse_nmap_grepable_line(line):
                key = (row["host"], row["port"])
                if key in seen:
                    continue
                seen.add(key)
                svc = row.get("service", "")
                ver = row.get("version", "")
                sev = _severity_for_exposed_service(svc, ver)
                tgt_host = row["host"] or host
                target = f"{tgt_host}:{row['port']}"
                out.append(
                    Finding(
                        target=target,
                        vulnerability_type="exposed_service",
                        severity=sev,
                        evidence={
                            "protocol": row.get("protocol", "tcp"),
                            "service": svc,
                            "version": ver,
                            "nmap_grepable": line[:2000],
                        },
                        source_scanner=self.name,
                        title=f"Service {svc or 'unknown'} on tcp/{row['port']}",
                        description="nmap -sV fingerprint. Map version to CVEs (searchsploit, NVD) or run nuclei with relevant templates; optional scanning.nmap_scripts for NSE checks.",
                    )
                )
        return out


class FfufScannerPlugin(ScannerPlugin):
    """Directory/parameter fuzzing — requires scanning.ffuf_wordlist in config."""

    name = "ffuf_scanner"
    version = "1.0.0"
    scan_tier = "aggressive"

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
        proc = _run_tool_ctx(
            context,
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
            tool_label="ffuf",
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


def _vhost_ffuf_target_url(identifier: str) -> tuple[str, str] | None:
    """
    Build ffuf -u URL for vhost discovery: https://<IP>/ per
    https://github.com/ffuf/ffuf#virtual-host-discovery-without-dns-records
    Hostnames are resolved to the first A/AAAA record.
    """
    h = identifier.strip()
    try:
        addr = ipaddress.ip_address(h)
        if isinstance(addr, ipaddress.IPv6Address):
            return f"https://[{h}]/", h
        return f"https://{h}/", h
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(h, "https", type=socket.SOCK_STREAM)
    except OSError:
        return None
    for fam, _, _, _, sockaddr in infos:
        if fam == socket.AF_INET:
            ip = sockaddr[0]
            return f"https://{ip}/", ip
        if fam == socket.AF_INET6:
            ip = sockaddr[0]
            return f"https://[{ip}]/", ip
    return None


class VhostFfufScannerPlugin(ScannerPlugin):
    """
    Virtual host enumeration via ffuf: -H \"Host: FUZZ\" against https://<resolved-ip>/
    (see ffuf README \"Virtual host discovery\"). Wordlist entries may use %s for the apex domain
    (e.g. Avileox gist: https://gist.github.com/Avileox/941f5eb742bad690d04c16b78ac41b57).

    The pipeline runs this scanner **only on the root/apex domain** (one ffuf job per run), not on
    every discovered subdomain. Subdomains are ignored for this plugin.
    """

    name = "vhost_ffuf_scanner"
    scan_tier = "aggressive"
    version = "1.0.0"

    @staticmethod
    def _bundled_vhost_wordlist() -> Path:
        return Path(__file__).resolve().parent.parent / "data" / "wl-vhost.txt"

    @staticmethod
    def _write_processed_wordlist(source: Path, apex: str) -> Path:
        apex = apex.lower().strip().rstrip(".")
        text = source.read_text(encoding="utf-8", errors="replace")
        tmp = tempfile.NamedTemporaryFile(
            "w",
            suffix=".txt",
            delete=False,
            encoding="utf-8",
            newline="\n",
            prefix="recon-vhost-",
        )
        path = Path(tmp.name)
        try:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                tmp.write(line.replace("%s", apex) + "\n")
            tmp.close()
            return path
        except Exception:
            tmp.close()
            path.unlink(missing_ok=True)
            raise

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"stdout": ""})
        host = targets[0].identifier.strip()
        apex = (context.domain or "").strip().lower().rstrip(".")
        if not apex:
            return RawScanResult(
                scanner_name=self.name,
                targets=[host],
                success=False,
                error_message="vhost_ffuf needs scan domain / apex for %s substitution.",
                raw_payload={},
            )
        wl_cfg = str(context.metadata.get("vhost_ffuf_wordlist", "") or "").strip()
        wl_path = Path(wl_cfg).expanduser() if wl_cfg else self._bundled_vhost_wordlist()
        if not wl_path.is_file():
            return RawScanResult(
                scanner_name=self.name,
                targets=[host],
                success=False,
                error_message=f"vhost wordlist not found: {wl_path} — set scanning.vhost_ffuf_wordlist",
                raw_payload={},
            )
        resolved = _vhost_ffuf_target_url(host)
        if not resolved:
            return RawScanResult(
                scanner_name=self.name,
                targets=[host],
                success=False,
                error_message=f"Could not resolve '{host}' to an IP for vhost fuzzing.",
                raw_payload={},
            )
        target_url, ip_label = resolved
        processed: Path | None = None
        try:
            processed = self._write_processed_wordlist(wl_path, apex)
        except OSError as e:
            return RawScanResult(
                scanner_name=self.name,
                targets=[host],
                success=False,
                error_message=f"vhost wordlist prepare failed: {e}",
                raw_payload={},
            )
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "ffuf", "ffuf")
        fs = context.metadata.get("vhost_ffuf_filter_size")
        try:
            fs_int = int(fs) if fs is not None and str(fs).strip() != "" else None
        except (TypeError, ValueError):
            fs_int = None
        autocalibrate = bool(context.metadata.get("vhost_ffuf_autocalibrate", True))
        argv: list[str] = [
            bin_path,
            "-w",
            str(processed),
            "-u",
            target_url,
            "-H",
            "Host: FUZZ",
            "-json",
            "-s",
            "-noninteractive",
            "-t",
            "20",
            "-timeout",
            "10",
        ]
        if fs_int is not None:
            argv.extend(["-fs", str(fs_int)])
        elif autocalibrate:
            argv.append("-ac")
        try:
            proc = _run_tool_ctx(
                context,
                argv,
                timeout=_timeout(ctx=context, default=600),
                tool_label="ffuf-vhost",
            )
        finally:
            if processed is not None:
                processed.unlink(missing_ok=True)
        ok = proc.returncode == 0 or bool(proc.stdout.strip())
        return RawScanResult(
            scanner_name=self.name,
            targets=[host],
            success=ok,
            raw_payload={
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "vhost_target_ip": ip_label,
                "vhost_source_asset": host,
            },
            error_message=None if ok else (proc.stderr or f"ffuf exit {proc.returncode}")[:2000],
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        out: list[Finding] = []
        ip = raw.raw_payload.get("vhost_target_ip", "")
        src = raw.raw_payload.get("vhost_source_asset", "")
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
            fuzz_input = row.get("input") or {}
            host_hdr = ""
            if isinstance(fuzz_input, dict):
                host_hdr = fuzz_input.get("FUZZ") or fuzz_input.get("Host") or ""
                if not host_hdr and len(fuzz_input) == 1:
                    v = next(iter(fuzz_input.values()))
                    host_hdr = v if isinstance(v, str) else str(v)
            elif isinstance(fuzz_input, str):
                host_hdr = fuzz_input
            sc = row.get("status")
            url = row.get("url", "")
            if host_hdr:
                out.append(
                    Finding(
                        target=str(host_hdr),
                        vulnerability_type="vhost_candidate",
                        severity=Severity.INFO,
                        evidence={
                            "status": sc,
                            "length": row.get("length"),
                            "request_url": url,
                            "probed_ip": ip,
                            "source_asset": src,
                        },
                        source_scanner=self.name,
                        title="Possible virtual host (ffuf Host fuzz)",
                        description=f"Host header candidate against {ip} (asset {src}). "
                        "Confirm manually; tune -fs or -ac if noisy.",
                    )
                )
        return out


class SecretFinderScannerPlugin(ScannerPlugin):
    """Runs SecretFinder against one origin — set scanning.secretfinder_script (Python script path)."""

    name = "secretfinder_scanner"
    version = "1.0.0"
    _warned_missing_script: bool = False

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        script = str(context.metadata.get("secretfinder_script", "") or "").strip()
        py = resolve_binary(context.metadata.get("tool_paths") or {}, "python3", "python3")
        if not script or not Path(script).is_file():
            if not SecretFinderScannerPlugin._warned_missing_script:
                SecretFinderScannerPlugin._warned_missing_script = True
                log.info(
                    "secretfinder_scanner: no scanning.secretfinder_script — skipping "
                    "(set path to SecretFinder.py to run)"
                )
            return RawScanResult(
                scanner_name=self.name,
                success=True,
                raw_payload={"stdout": "", "skipped_no_script": True},
            )
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={"stdout": ""})
        host = targets[0].identifier.strip()
        url = f"https://{host}"
        proc = _run_tool_ctx(
            context,
            [py, script, "-i", url, "-o", "cli"],
            timeout=_timeout(ctx=context, default=300),
            tool_label="secretfinder",
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
