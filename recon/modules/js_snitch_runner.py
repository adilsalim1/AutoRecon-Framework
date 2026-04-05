"""
Run a js-snitch–style pipeline on URLs already collected by the framework (gau, wayback, etc.).

Upstream `js_snitch.py` only accepts hostnames and scrapes `https://host/` for <script src>.
We download every deduplicated JS URL, mirror tmp/beautify + TruffleHog + Semgrep per
https://github.com/vavkamil/js-snitch
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from recon.core.logger import get_logger
from recon.models.findings import Finding, Severity
from recon.utils.tool_runner import resolve_binary, run_tool

log = get_logger("js_snitch")

USER_AGENT = "AutoRecon-JSSnitch/1.0 (+https://github.com/vavkamil/js-snitch)"


def _resolve_cli(tool_paths: dict[str, str], key: str, default_name: str) -> str | None:
    candidate = resolve_binary(tool_paths, key, default_name)
    p = Path(candidate)
    if p.is_file():
        return str(p.resolve())
    w = shutil.which(candidate) or shutil.which(default_name)
    return w


def _sha10(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:10]


def _safe_js_filename(url: str, idx: int) -> str:
    digest = _sha10(url)
    try:
        path = urlparse(url).path.split("?")[0] or "script"
        base = Path(path).name or "script.js"
        if not base.endswith(".js"):
            base = f"{base}.js"
        base = "".join(c if c.isalnum() or c in "._-" else "_" for c in base)[:80]
    except ValueError:
        base = "script.js"
    return f"{idx:04d}_{digest}_{base}"


def _url_for_beautify_name(name: str, digest_to_url: dict[str, str]) -> str:
    parts = name.split("_", 2)
    if len(parts) >= 2 and len(parts[1]) == 10:
        return digest_to_url.get(parts[1], name)
    return name


def _download_js(url: str, dest: Path, timeout: int) -> bool:
    try:
        req = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read(5_000_000)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        return True
    except Exception as e:
        log.debug("js-snitch download failed %s: %s", url[:120], e)
        return False


def _beautify_or_copy(tmp_path: Path, beautify_path: Path) -> None:
    try:
        import jsbeautifier  # type: ignore[import-untyped]

        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        text = tmp_path.read_text(encoding="utf-8", errors="replace")
        beautify_path.parent.mkdir(parents=True, exist_ok=True)
        beautify_path.write_text(
            jsbeautifier.beautify(text, opts), encoding="utf-8", errors="replace"
        )
    except Exception:
        beautify_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp_path, beautify_path)


def _parse_trufflehog_jsonl(path: Path) -> list[dict]:
    secrets: list[dict] = []
    if not path.is_file():
        return secrets
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        fn = (
            data.get("SourceMetadata", {})
            .get("Data", {})
            .get("Filesystem", {})
            .get("file", "")
        )
        secrets.append(
            {
                "filename": fn,
                "detector_name": data.get("DetectorName", ""),
                "verified": bool(data.get("Verified", False)),
                "raw_len": len(str(data.get("Raw", ""))),
            }
        )
    dedup: dict[str, dict] = {}
    for s in secrets:
        key = f"{s.get('filename')}:{s.get('detector_name')}"
        prev = dedup.get(key)
        if prev is None or (s.get("verified") and not prev.get("verified")):
            dedup[key] = s
    return list(dedup.values())


def _parse_semgrep_json(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    for result in data.get("results") or []:
        out.append(
            {
                "path": result.get("path", ""),
                "check_id": result.get("check_id", ""),
                "severity": (result.get("extra") or {}).get("severity", ""),
                "message": (result.get("extra") or {}).get("message", ""),
                "lines": (result.get("extra") or {}).get("lines", ""),
            }
        )
    return out


def _semgrep_severity(s: str) -> Severity:
    s = (s or "").upper()
    if s in ("ERROR", "CRITICAL"):
        return Severity.HIGH
    if s == "WARNING":
        return Severity.MEDIUM
    return Severity.INFO


def run_js_snitch_on_urls(
    js_urls: list[str],
    *,
    tool_paths: dict[str, str],
    timeout_seconds: int = 30,
    max_urls: int = 500,
    js_snitch_repo: str = "",
    subprocess_timeout_trufflehog: int = 900,
    subprocess_timeout_semgrep: int = 600,
    stream_subprocess_output: bool = False,
) -> list[Finding]:
    """
    Download JS URLs, beautify, run TruffleHog filesystem + Semgrep (same flow as js-snitch).

    Requires `trufflehog` and `semgrep` on PATH or under tools.* in config.
    Optional `js_snitch_repo`: path to cloned vavkamil/js-snitch for `custom-semgrep-templates`.
    """
    if not js_urls:
        return []

    th_bin = _resolve_cli(tool_paths, "trufflehog", "trufflehog")
    sg_bin = _resolve_cli(tool_paths, "semgrep", "semgrep")
    if not th_bin:
        log.warning(
            "js-snitch: trufflehog not found — install "
            "https://github.com/trufflesecurity/trufflehog or set tools.trufflehog; skipping"
        )
        return []
    if not sg_bin:
        log.warning(
            "js-snitch: semgrep not found — set tools.semgrep or pip install semgrep; skipping"
        )
        return []

    seen: set[str] = set()
    ordered: list[str] = []
    for u in js_urls:
        u = (u or "").strip()
        if not u.startswith("http") or u in seen:
            continue
        seen.add(u)
        ordered.append(u)
        if len(ordered) >= max(1, max_urls):
            break

    digest_to_url: dict[str, str] = {_sha10(u): u for u in ordered}

    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="recon_js_snitch_") as tmp_root:
        root = Path(tmp_root)
        tmp_dir = root / "tmp"
        beautify_dir = root / "beautify"
        tmp_dir.mkdir(parents=True)
        beautify_dir.mkdir(parents=True)

        ok = 0
        for i, url in enumerate(ordered):
            name = _safe_js_filename(url, i)
            tpath = tmp_dir / name
            if not _download_js(url, tpath, timeout_seconds):
                continue
            bpath = beautify_dir / name
            _beautify_or_copy(tpath, bpath)
            ok += 1

        if ok == 0:
            log.info("js-snitch: no JS files downloaded from %s URL(s)", len(ordered))
            return []

        log.info("js-snitch: scanning %s JS file(s) with TruffleHog + Semgrep", ok)

        secrets_json = root / "secrets.json"
        argv_th = [
            th_bin,
            "filesystem",
            "--directory",
            str(beautify_dir),
            "--json",
        ]
        proc_th = run_tool(
            argv_th,
            timeout=max(120, subprocess_timeout_trufflehog),
            live_output=stream_subprocess_output,
            live_prefix="trufflehog",
        )
        if proc_th.returncode != 0 and not (proc_th.stdout or "").strip():
            log.debug("trufflehog: exit %s", proc_th.returncode)
        secrets_json.write_text(proc_th.stdout or "", encoding="utf-8")

        for s in _parse_trufflehog_jsonl(secrets_json):
            verified = s.get("verified", False)
            fn = s.get("filename") or ""
            base = Path(fn).name if fn else ""
            src_url = _url_for_beautify_name(base, digest_to_url) if base else ""
            findings.append(
                Finding(
                    target=src_url or fn or "js",
                    vulnerability_type="secret_js_snitch_trufflehog",
                    severity=Severity.HIGH if verified else Severity.MEDIUM,
                    evidence={
                        "detector": s.get("detector_name"),
                        "verified": verified,
                        "scan_file": fn,
                    },
                    source_scanner="js_snitch",
                    title=f"TruffleHog: {s.get('detector_name') or 'secret'}",
                    description=(
                        "Secret candidate in remote JS (TruffleHog, js-snitch flow). "
                        "Verify manually."
                    ),
                    source_ref=src_url or fn,
                    confidence=0.85 if verified else 0.45,
                    exploitability="unknown",
                )
            )

        semgrep_json = root / "semgrep_output.json"
        semgrep_cmd: list[str] = [
            sg_bin,
            "scan",
            "--no-rewrite-rule-ids",
            "--config",
            "r/generic.secrets",
        ]
        repo = (js_snitch_repo or "").strip()
        custom = Path(repo) / "custom-semgrep-templates" if repo else None
        if custom and custom.is_dir():
            semgrep_cmd.extend(["--config", str(custom)])
        semgrep_cmd.extend(
            [
                str(beautify_dir),
                "--json",
                "--output",
                str(semgrep_json),
            ]
        )

        proc_sg = run_tool(
            semgrep_cmd,
            timeout=max(120, subprocess_timeout_semgrep),
            live_output=stream_subprocess_output,
            live_prefix="semgrep",
        )
        if proc_sg.returncode not in (0, 1):
            log.debug("semgrep: exit %s", proc_sg.returncode)

        for row in _parse_semgrep_json(semgrep_json):
            path = row.get("path") or ""
            base = Path(path).name if path else ""
            src_url = _url_for_beautify_name(base, digest_to_url) if base else path
            findings.append(
                Finding(
                    target=src_url or path or "semgrep",
                    vulnerability_type="secret_js_snitch_semgrep",
                    severity=_semgrep_severity(row.get("severity", "")),
                    evidence={
                        "check_id": row.get("check_id"),
                        "message": (row.get("message") or "")[:500],
                        "lines": str(row.get("lines") or "")[:500],
                    },
                    source_scanner="js_snitch",
                    title=f"Semgrep: {row.get('check_id', 'finding')}",
                    description="Semgrep generic secrets rule on collected JS (js-snitch flow).",
                    source_ref=src_url or path,
                    confidence=0.5,
                    exploitability="unknown",
                )
            )

    return findings
