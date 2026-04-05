from __future__ import annotations

import shutil
import sys
from pathlib import Path
from urllib.request import Request, urlopen

from recon.core.logger import get_logger
from recon.models.findings import Finding, Severity
from recon.modules.secrets.detector import SecretDetector
from recon.utils.tool_runner import run_tool

log = get_logger("js_analysis")


class JsAnalysisEngine:
    """
    Fetch JS URLs (best-effort), run regex secret detection, optionally invoke LinkFinder CLI.
    SecretFinder-style analysis can reuse scanning.secretfinder_script via run_secretfinder_batch.
    """

    def __init__(
        self,
        *,
        fetch_timeout: int = 25,
        max_js_urls: int = 40,
        stream_subprocess_output: bool = True,
    ) -> None:
        self._fetch_timeout = max(5, fetch_timeout)
        self._max_js = max(1, max_js_urls)
        self._stream = stream_subprocess_output
        self._detector = SecretDetector()

    def _fetch_body(self, url: str) -> str | None:
        try:
            req = Request(
                url,
                headers={"User-Agent": "AutoRecon-JSAnalysis/1.0"},
                method="GET",
            )
            with urlopen(req, timeout=self._fetch_timeout) as resp:
                raw = resp.read(800_000)
            return raw.decode("utf-8", errors="replace")
        except Exception as e:
            log.debug("fetch js failed %s: %s", url, e)
            return None

    def _run_linkfinder(self, js_url: str, script_path: str) -> list[str]:
        py = shutil.which("python3") or shutil.which("python") or sys.executable
        sp = Path(script_path).expanduser()
        if not sp.is_file():
            return []
        try:
            proc = run_tool(
                [py, str(sp), "-i", js_url, "-o", "cli"],
                timeout=120,
                live_output=self._stream,
                live_prefix="linkfinder",
            )
        except (FileNotFoundError, OSError) as e:
            log.warning("linkfinder: %s", e)
            return []
        endpoints: list[str] = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("http") or line.startswith("/"):
                endpoints.append(line)
        return endpoints

    def analyze(
        self,
        js_urls: list[str],
        *,
        linkfinder_script: str = "",
        parent_domain: str = "",
    ) -> list[Finding]:
        findings: list[Finding] = []
        for js_url in js_urls[: self._max_js]:
            body = self._fetch_body(js_url)
            if body:
                findings.extend(
                    self._detector.scan_text(
                        body,
                        source_ref=js_url,
                        source_scanner="js_analysis",
                    )
                )
            lf = (linkfinder_script or "").strip()
            if lf and body:
                for ep in self._run_linkfinder(js_url, lf)[:200]:
                    findings.append(
                        Finding(
                            target=ep if ep.startswith("http") else f"{js_url}#{ep}",
                            vulnerability_type="linkfinder_endpoint",
                            severity=Severity.INFO,
                            evidence={"endpoint": ep, "js_source": js_url},
                            source_scanner="js_analysis",
                            title="Endpoint extracted from JS (LinkFinder)",
                            source_ref=js_url,
                            confidence=0.55,
                            exploitability="unknown",
                        )
                    )
        for f in findings:
            if not f.description:
                f.description = f.source_scanner
            if parent_domain and not f.evidence.get("parent_domain"):
                ev = dict(f.evidence)
                ev["parent_domain"] = parent_domain
                f.evidence = ev
        return findings
