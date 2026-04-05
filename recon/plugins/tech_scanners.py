"""
Optional technology profilers (free / local CLIs only):

- WhatWeb: apt install whatweb (Debian/Ubuntu) or https://github.com/urbanadventurer/WhatWeb
- Wappalyzer: npm i -g wappalyzer (or set tools.wappalyzer to your CLI path)
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from recon.models.assets import Asset
from recon.models.findings import Finding, Severity
from recon.plugins.base import RawScanResult, ScanContext, ScannerPlugin
from recon.utils.tool_runner import resolve_binary, run_tool


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
    return run_tool(
        argv,
        timeout=timeout,
        stdin_text=stdin_text,
        live_output=bool(ctx.metadata.get("stream_subprocess_output", True)),
        live_prefix=tool_label,
    )


def _urls_for_host(host: str) -> list[tuple[str, str]]:
    h = host.strip()
    return [("https", f"https://{h}/"), ("http", f"http://{h}/")]


def _parse_whatweb_json(data: Any) -> list[dict[str, Any]]:
    """Extract plugin fingerprints from WhatWeb --log-json structure."""
    out: list[dict[str, Any]] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, list):
            for x in obj:
                walk(x)
        elif isinstance(obj, dict):
            plugins = obj.get("plugins")
            if isinstance(plugins, dict):
                for plugin_name, detail in plugins.items():
                    out.append({"name": str(plugin_name), "detail": detail})
            for k, v in obj.items():
                if k != "plugins":
                    walk(v)

    walk(data)
    return out


def _parse_whatweb_text(text: str) -> list[dict[str, Any]]:
    """Fallback when JSON logging is unavailable: bracket tokens."""
    out: list[dict[str, Any]] = []
    for m in re.finditer(r"\[([^\]]{1,120})\]", text):
        chunk = m.group(1).strip()
        if chunk and not chunk.isdigit() and len(chunk) > 1:
            if "," in chunk and "[" not in chunk:
                for part in chunk.split(","):
                    p = part.strip()
                    if p and len(p) < 80:
                        out.append({"name": p, "detail": None})
            else:
                out.append({"name": chunk, "detail": None})
    seen: set[str] = set()
    dedup: list[dict[str, Any]] = []
    for row in out:
        k = row["name"].lower()
        if k in seen:
            continue
        seen.add(k)
        dedup.append(row)
    return dedup[:80]


class WhatWebScannerPlugin(ScannerPlugin):
    name = "whatweb_scanner"
    version = "1.0.0"
    scan_tier = "safe"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={})
        host = targets[0].identifier.strip()
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "whatweb", "whatweb")
        timeout = max(60, _timeout(ctx=context, default=180))
        last_err = ""
        for scheme, url in _urls_for_host(host):
            proc = _run_tool_ctx(
                context,
                [
                    bin_path,
                    "--no-errors",
                    "--log-json=-",
                    url,
                ],
                timeout=timeout,
                tool_label="whatweb",
            )
            out = (proc.stdout or "").strip()
            last_err = proc.stderr or last_err
            if out:
                return RawScanResult(
                    scanner_name=self.name,
                    targets=[host],
                    success=True,
                    raw_payload={"stdout": out, "url": url, "scheme": scheme},
                )
        proc2 = _run_tool_ctx(
            context,
            [bin_path, "--no-errors", f"https://{host}/"],
            timeout=timeout,
            tool_label="whatweb",
        )
        txt = (proc2.stdout or "").strip()
        if txt:
            return RawScanResult(
                scanner_name=self.name,
                targets=[host],
                success=True,
                raw_payload={"stdout": txt, "text_fallback": True, "url": f"https://{host}/"},
            )
        return RawScanResult(
            scanner_name=self.name,
            targets=[host],
            success=False,
            error_message=(last_err or "whatweb produced no output")[:2000],
            raw_payload={},
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        text = raw.raw_payload.get("stdout", "") or ""
        url = str(raw.raw_payload.get("url") or raw.targets[0] if raw.targets else "")
        tech_rows: list[dict[str, Any]] = []
        if raw.raw_payload.get("text_fallback"):
            tech_rows = _parse_whatweb_text(text)
        else:
            try:
                data = json.loads(text)
                tech_rows = _parse_whatweb_json(data)
            except json.JSONDecodeError:
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        tech_rows.extend(_parse_whatweb_json(json.loads(line)))
                    except json.JSONDecodeError:
                        continue
                if not tech_rows:
                    tech_rows = _parse_whatweb_text(text)
        names = [t["name"] for t in tech_rows[:100]]
        if not names and not text:
            return []
        return [
            Finding(
                target=url,
                vulnerability_type="technology_profile",
                severity=Severity.INFO,
                evidence={
                    "profiler": "whatweb",
                    "technologies": names,
                    "raw_sample": text[:6000],
                },
                source_scanner=self.name,
                title="WhatWeb technology profile",
                description="Fingerprint via WhatWeb CLI.",
            )
        ]


class WappalyzerScannerPlugin(ScannerPlugin):
    name = "wappalyzer_scanner"
    version = "1.0.0"
    scan_tier = "safe"

    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        if not targets:
            return RawScanResult(scanner_name=self.name, success=True, raw_payload={})
        host = targets[0].identifier.strip()
        bin_path = resolve_binary(context.metadata.get("tool_paths") or {}, "wappalyzer", "wappalyzer")
        timeout = max(60, _timeout(ctx=context, default=240))
        last_err = ""
        for _scheme, url in _urls_for_host(host):
            with tempfile.NamedTemporaryFile(
                "w", suffix=".txt", delete=False, encoding="utf-8"
            ) as url_f:
                url_f.write(url + "\n")
                url_file = url_f.name
            json_fd, json_file = tempfile.mkstemp(suffix=".json")
            os.close(json_fd)
            try:
                proc = _run_tool_ctx(
                    context,
                    [bin_path, "-i", url_file, "-oJ", json_file],
                    timeout=timeout,
                    tool_label="wappalyzer",
                )
                out = Path(json_file).read_text(encoding="utf-8", errors="replace").strip()
                if not out:
                    out = (proc.stdout or "").strip()
                last_err = proc.stderr or last_err
            finally:
                Path(url_file).unlink(missing_ok=True)
                Path(json_file).unlink(missing_ok=True)
            if out and out.startswith("["):
                return RawScanResult(
                    scanner_name=self.name,
                    targets=[host],
                    success=True,
                    raw_payload={"stdout": out, "url": url},
                )
            if out and "{" in out:
                return RawScanResult(
                    scanner_name=self.name,
                    targets=[host],
                    success=True,
                    raw_payload={"stdout": out, "url": url},
                )
        return RawScanResult(
            scanner_name=self.name,
            targets=[host],
            success=False,
            error_message=(
                last_err or "wappalyzer produced no JSON; install CLI (e.g. npm i -g wappalyzer)"
            )[:2000],
            raw_payload={},
        )

    def parse(self, raw: RawScanResult) -> list[Finding]:
        text = raw.raw_payload.get("stdout", "") or ""
        url = str(raw.raw_payload.get("url") or (raw.targets[0] if raw.targets else ""))
        techs: list[dict[str, Any]] = []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        rows = data if isinstance(data, list) else [data]
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = row.get("name") or row.get("technology", {}).get("name")
            if name:
                techs.append(
                    {
                        "name": str(name),
                        "version": row.get("version"),
                        "categories": row.get("categories") or row.get("category"),
                    }
                )
        if not techs:
            return []
        return [
            Finding(
                target=url,
                vulnerability_type="technology_profile",
                severity=Severity.INFO,
                evidence={
                    "profiler": "wappalyzer",
                    "technologies": techs[:80],
                },
                source_scanner=self.name,
                title="Wappalyzer technology profile",
                description="Fingerprint via Wappalyzer CLI.",
            )
        ]
