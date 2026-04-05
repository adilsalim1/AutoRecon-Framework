from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path


def resolve_binary(tool_paths: dict[str, str], key: str, default: str | None = None) -> str:
    """Prefer explicit config path (file on disk); else use CLI name from PATH."""
    val = (tool_paths.get(key) or "").strip()
    if not val:
        return default or key
    p = Path(val).expanduser()
    if p.is_file():
        return str(p.resolve())
    return val


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
