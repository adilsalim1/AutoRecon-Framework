from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

# Use stdlib logger only here to avoid importing recon.core (circular via plugins/registry).
_log = logging.getLogger("recon.tool_runner")

# httpx -h output → is this ProjectDiscovery's CLI (not Encode/python-httpx)?
_HTTPX_PD_CACHE: dict[str, bool] = {}


def resolve_binary(tool_paths: dict[str, str], key: str, default: str | None = None) -> str:
    """Prefer explicit config path (file on disk); else use CLI name from PATH."""
    val = (tool_paths.get(key) or "").strip()
    if not val:
        return default or key
    p = Path(val).expanduser()
    if p.is_file():
        return str(p.resolve())
    return val


def _httpx_help_looks_like_projectdiscovery(text: str) -> bool:
    """Distinguish ProjectDiscovery httpx from Encode's `httpx` CLI (positional URL only)."""
    t = (text or "").lower()
    if re.search(r"usage:\s*httpx\s+\[options\]\s+url\b", t):
        return False
    if "projectdiscovery" in t or "project discovery" in t:
        return True
    if "-silent" in t and "-json" in t:
        return True
    if re.search(r"[\s,/-]-u[\s,]", t):
        return True
    return False


def httpx_binary_is_projectdiscovery(bin_path: str) -> bool:
    """True if `bin_path -h` looks like ProjectDiscovery httpx (cached)."""
    if bin_path in _HTTPX_PD_CACHE:
        return _HTTPX_PD_CACHE[bin_path]
    try:
        proc = run_tool([bin_path, "-h"], timeout=15, live_output=False)
    except (FileNotFoundError, OSError):
        _HTTPX_PD_CACHE[bin_path] = False
        return False
    merged = (proc.stdout or "") + (proc.stderr or "")
    ok = _httpx_help_looks_like_projectdiscovery(merged)
    _HTTPX_PD_CACHE[bin_path] = ok
    return ok


def _go_bin_httpx_candidates() -> list[str]:
    """Absolute paths where `go install` typically places httpx."""
    out: list[str] = []
    seen: set[str] = set()

    def add_file(path: Path) -> None:
        try:
            path = path.expanduser()
            if path.is_file():
                s = str(path.resolve())
                if s not in seen:
                    seen.add(s)
                    out.append(s)
        except OSError:
            pass

    gp = os.environ.get("GOPATH", "").strip()
    if gp:
        add_file(Path(gp) / "bin" / "httpx")
    try:
        r = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        line = (r.stdout or "").strip().splitlines()
        if line:
            add_file(Path(line[0]) / "bin" / "httpx")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    add_file(Path.home() / "go" / "bin" / "httpx")
    return out


def resolve_httpx_binary(tool_paths: dict[str, str]) -> str:
    """
    Resolve httpx for scanning: explicit `tools.httpx` only if it is ProjectDiscovery
    httpx; otherwise prefer `$(go env GOPATH)/bin/httpx`, then any PATH `httpx` that
    passes the PD heuristic (never return pip's Encode httpx if a PD binary exists).
    """
    explicit = (tool_paths.get("httpx") or "").strip()
    if explicit:
        p = Path(explicit).expanduser()
        if p.is_file():
            chosen = str(p.resolve())
            if httpx_binary_is_projectdiscovery(chosen):
                return chosen
            _log.warning(
                "tools.httpx (%s) is not ProjectDiscovery httpx — trying Go-installed binary. "
                "Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
                chosen,
            )
        else:
            resolved = shutil.which(explicit) or explicit
            if httpx_binary_is_projectdiscovery(resolved):
                return resolved
            _log.warning(
                "tools.httpx (%r) resolves to %r, which is not ProjectDiscovery httpx "
                "(often `pip install httpx`). Trying Go bin/httpx next.",
                explicit,
                resolved,
            )

    for cand in _go_bin_httpx_candidates():
        if httpx_binary_is_projectdiscovery(cand):
            _log.info("Using ProjectDiscovery httpx at %s", cand)
            return cand

    which = shutil.which("httpx")
    if which and httpx_binary_is_projectdiscovery(which):
        return which
    if which:
        _log.warning(
            "`httpx` on PATH (%s) is not ProjectDiscovery httpx. "
            "Run: go install github.com/projectdiscovery/httpx/cmd/httpx@latest "
            "and set tools.httpx to the full path from `go env GOPATH`/bin/httpx.",
            which,
        )
    return which or explicit or "httpx"


def run_tool(
    argv: list[str],
    *,
    timeout: int,
    stdin_text: str | None = None,
    cwd: str | Path | None = None,
    live_output: bool = False,
    live_prefix: str = "",
) -> subprocess.CompletedProcess[str]:
    """
    Run a subprocess. When live_output is True, stream stdout/stderr to this process's stderr
    (prefixed) while capturing full output for parsers.
    """
    if not live_output:
        return subprocess.run(
            argv,
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    return _run_tool_live(
        argv,
        timeout=timeout,
        stdin_text=stdin_text,
        cwd=cwd,
        prefix=live_prefix or (Path(argv[0]).name if argv else "tool"),
    )


def _run_tool_live(
    argv: list[str],
    *,
    timeout: int,
    stdin_text: str | None,
    cwd: str | Path | None,
    prefix: str,
) -> subprocess.CompletedProcess[str]:
    stdin_arg = subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL
    proc = subprocess.Popen(
        argv,
        stdin=stdin_arg,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
        bufsize=1,
    )
    if stdin_text is not None and proc.stdin:
        proc.stdin.write(stdin_text)
        proc.stdin.close()

    out_buf: list[str] = []
    err_buf: list[str] = []

    def pump(stream, chunks: list[str], label: str) -> None:
        try:
            for line in iter(stream.readline, ""):
                chunks.append(line)
                print(f"[{label}] {line}", end="", file=sys.stderr, flush=True)
        finally:
            try:
                stream.close()
            except Exception:
                pass

    t_out = threading.Thread(
        target=pump,
        args=(proc.stdout, out_buf, f"{prefix}:stdout"),
        daemon=True,
    )
    t_err = threading.Thread(
        target=pump,
        args=(proc.stderr, err_buf, f"{prefix}:stderr"),
        daemon=True,
    )
    t_out.start()
    t_err.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=15)
        except Exception:
            pass
        t_out.join(timeout=5)
        t_err.join(timeout=5)
        return subprocess.CompletedProcess(
            argv,
            124,
            "".join(out_buf),
            "".join(err_buf) + "\n[recon: subprocess timeout]\n",
        )

    rc = proc.returncode if proc.returncode is not None else -1
    t_out.join(timeout=120)
    t_err.join(timeout=120)
    return subprocess.CompletedProcess(argv, rc, "".join(out_buf), "".join(err_buf))
