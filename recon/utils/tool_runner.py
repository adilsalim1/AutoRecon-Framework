from __future__ import annotations

import subprocess
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
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        check=False,
    )
