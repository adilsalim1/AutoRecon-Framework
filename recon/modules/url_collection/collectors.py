"""
Thin subprocess adapters for URL sources. Each returns newline-delimited URLs (best-effort).
Tools must be on PATH or configured under tools.* in AppConfig.
"""

from __future__ import annotations

from recon.core.logger import get_logger
from recon.utils.tool_runner import resolve_binary, run_tool

log = get_logger("url_collectors")


def collect_gau(domain: str, tool_paths: dict[str, str], timeout: int, stream: bool) -> list[str]:
    bin_path = resolve_binary(tool_paths, "gau", "gau")
    try:
        proc = run_tool(
            [bin_path, domain],
            timeout=timeout,
            live_output=stream,
            live_prefix="gau",
        )
    except (FileNotFoundError, OSError) as e:
        log.warning("gau failed: %s", e)
        return []
    if proc.returncode != 0 and not (proc.stdout or "").strip():
        log.warning("gau exit %s", proc.returncode)
    return [x.strip() for x in (proc.stdout or "").splitlines() if x.strip()]


def collect_waybackurls(domain: str, tool_paths: dict[str, str], timeout: int, stream: bool) -> list[str]:
    bin_path = resolve_binary(tool_paths, "waybackurls", "waybackurls")
    try:
        proc = run_tool(
            [bin_path],
            timeout=timeout,
            stdin_text=domain.strip() + "\n",
            live_output=stream,
            live_prefix="waybackurls",
        )
    except (FileNotFoundError, OSError) as e:
        log.warning("waybackurls failed: %s", e)
        return []
    return [x.strip() for x in (proc.stdout or "").splitlines() if x.strip()]


def collect_katana(seed_url: str, tool_paths: dict[str, str], timeout: int, stream: bool) -> list[str]:
    bin_path = resolve_binary(tool_paths, "katana", "katana")
    try:
        proc = run_tool(
            [
                bin_path,
                "-u",
                seed_url,
                "-silent",
                "-jc",
                "-d",
                "2",
                "-timeout",
                "10",
            ],
            timeout=timeout,
            live_output=stream,
            live_prefix="katana",
        )
    except (FileNotFoundError, OSError) as e:
        log.warning("katana failed for %s: %s", seed_url, e)
        return []
    return [x.strip() for x in (proc.stdout or "").splitlines() if x.strip()]


def collect_hakrawler(seed_url: str, tool_paths: dict[str, str], timeout: int, stream: bool) -> list[str]:
    bin_path = resolve_binary(tool_paths, "hakrawler", "hakrawler")
    try:
        proc = run_tool(
            [bin_path, "-url", seed_url, "-depth", "2"],
            timeout=timeout,
            live_output=stream,
            live_prefix="hakrawler",
        )
    except (FileNotFoundError, OSError) as e:
        log.warning("hakrawler failed for %s: %s", seed_url, e)
        return []
    return [x.strip() for x in (proc.stdout or "").splitlines() if x.strip()]
