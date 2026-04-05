from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from recon.bootstrap.definitions import (
    TOOL_SPECS,
    ToolSpec,
    required_tool_keys_for_config,
    spec_for_key,
)
from recon.core.config_loader import AppConfig
from recon.core.logger import get_logger

log = get_logger("bootstrap")


def prepend_user_local_bin_to_path() -> None:
    """Prepend ~/.local/bin (typical pip --user scripts) to PATH."""
    if os.name == "nt":
        return
    local = Path.home() / ".local" / "bin"
    if local.is_dir():
        path = os.environ.get("PATH", "")
        s = str(local)
        if s not in path.split(os.pathsep):
            os.environ["PATH"] = s + os.pathsep + path


def prepend_go_bin_to_path() -> None:
    """Put $(go env GOPATH)/bin on PATH so freshly `go install`ed tools resolve."""
    try:
        proc = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return
    if proc.returncode != 0:
        return
    gopath = (proc.stdout or "").strip()
    if not gopath:
        return
    bin_dir = str(Path(gopath) / "bin")
    if Path(bin_dir).is_dir():
        path = os.environ.get("PATH", "")
        if bin_dir not in path.split(os.pathsep):
            os.environ["PATH"] = bin_dir + os.pathsep + path
            log.debug("prepended GOPATH/bin to PATH: %s", bin_dir)


def _is_debian_family() -> bool:
    """True on Debian, Ubuntu, and derivatives (apt-get)."""
    if Path("/etc/debian_version").is_file():
        return True
    rel = Path("/etc/os-release")
    if not rel.is_file():
        return False
    try:
        txt = rel.read_text(encoding="utf-8")
    except OSError:
        return False
    data: dict[str, str] = {}
    for line in txt.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, _, v = line.partition("=")
            data[k.strip()] = v.strip().strip('"')
    did = data.get("ID", "").lower()
    like = data.get("ID_LIKE", "").lower()
    return (
        did in ("debian", "ubuntu", "linuxmint", "pop", "kali")
        or "debian" in like
    )


def _which_any(names: tuple[str, ...]) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _have_tool_with_config(spec: ToolSpec, tool_paths: dict[str, str]) -> bool:
    cfg = (tool_paths.get(spec.key) or "").strip()
    if cfg:
        p = Path(cfg).expanduser()
        if p.is_file():
            return True
        if shutil.which(cfg):
            return True
    return bool(_which_any(spec.check_names))


def tool_check_detail(spec: ToolSpec, tool_paths: dict[str, str]) -> tuple[bool, str]:
    """
    Return (installed, message). Always checks first — no network or package managers.
    """
    cfg = (tool_paths.get(spec.key) or "").strip()
    if cfg:
        p = Path(cfg).expanduser()
        if p.is_file():
            return True, f"config path (file): {p.resolve()}"
        w = shutil.which(cfg)
        if w:
            return True, f"config path (name on PATH): {w}"
        return False, f"config path set but not found: {cfg}"
    w = _which_any(spec.check_names)
    if w:
        names = ", ".join(spec.check_names)
        return True, f"on PATH ({names}): {w}"
    return False, f"not found (looked for: {', '.join(spec.check_names)})"


def log_preflight_tools(keys: frozenset[str], tool_paths: dict[str, str], *, title: str) -> None:
    log.info("%s", title)
    if not keys:
        log.info("  (no external tools required for this configuration)")
        return
    for key in sorted(keys):
        spec = spec_for_key(key)
        if spec is None:
            log.info("  %-14s — unknown key (no installer recipe)", key)
            continue
        ok, detail = tool_check_detail(spec, tool_paths)
        status = "OK " if ok else "MISSING"
        log.info("  [%s] %-14s — %s", status, spec.key, detail)


def check_tools_for_config(config: AppConfig) -> tuple[bool, dict[str, tuple[bool, str]]]:
    """
    Check all tools required by the current config. Does not install anything.
    Returns (all_ok, {key: (installed, detail)}).
    """
    prepend_user_local_bin_to_path()
    prepend_go_bin_to_path()
    keys = required_tool_keys_for_config(
        list(config.discovery.providers),
        list(config.scanning.plugins),
    )
    results: dict[str, tuple[bool, str]] = {}
    all_ok = True
    for key in sorted(keys):
        spec = spec_for_key(key)
        if spec is None:
            results[key] = (False, "no installer recipe")
            all_ok = False
            continue
        ok, detail = tool_check_detail(spec, config.tool_paths)
        results[key] = (ok, detail)
        if not ok:
            all_ok = False
    return all_ok, results


def _run(
    cmd: list[str],
    timeout: int,
    *,
    env: dict[str, str] | None = None,
) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except FileNotFoundError as e:
        return 127, str(e)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out[-4000:]


def _have_go() -> bool:
    return shutil.which("go") is not None


def _ensure_go_compiler() -> bool:
    """
    Ensure the `go` command exists. On Debian/Kali/Ubuntu, try apt install golang-go once.
    Requires root or passwordless sudo (same as other apt bootstrap steps).
    """
    if _have_go():
        return True
    if not _is_debian_family():
        log.warning(
            "The 'go' command is not installed. Many tools need it (go install …). "
            "Install from https://go.dev/dl/ or use your OS package manager."
        )
        return False
    log.info(
        "Go compiler not found; installing Debian package golang-go (needed for go install …)"
    )
    ok, msg = _apt_install(("golang-go",), timeout=900)
    if not ok:
        log.warning("apt install golang-go failed: %s", msg)
        return False
    if not _have_go():
        log.warning(
            "golang-go finished but `go` is still not on PATH; try: hash -r or a new shell"
        )
        return False
    log.info("Go is available: %s", shutil.which("go"))
    return True


def _go_install(pkg: str, timeout: int = 900) -> tuple[bool, str]:
    if not _ensure_go_compiler():
        return (
            False,
            "go not available after bootstrap; on Debian/Kali: sudo apt install golang-go "
            "(or run this framework as root / with passwordless sudo for apt)",
        )
    prepend_go_bin_to_path()
    code, out = _run(["go", "install", "-v", pkg], timeout=timeout)
    prepend_go_bin_to_path()
    return code == 0, out


def _pip_install(req: str, timeout: int = 600) -> tuple[bool, str]:
    code, out = _run(
        [sys.executable, "-m", "pip", "install", "--upgrade", req],
        timeout=timeout,
    )
    return code == 0, out


def _apt_base_cmd() -> list[str] | None:
    """Return prefix for apt-get: [] if root, ['sudo','-n'] if passwordless sudo works."""
    if shutil.which("apt-get") is None:
        return None
    if os.geteuid() == 0:
        return []
    code, _ = _run(["sudo", "-n", "true"], timeout=10)
    if code == 0:
        return ["sudo", "-n"]
    return None


def _apt_install(packages: tuple[str, ...], timeout: int = 900) -> tuple[bool, str]:
    if not packages or not _is_debian_family():
        return False, "not a Debian-family OS or no packages"
    prefix = _apt_base_cmd()
    if prefix is None:
        return (
            False,
            "need root or passwordless sudo for apt-get (e.g. run in container as root, or visudo)",
        )
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    code, out = _run(
        prefix + ["apt-get", "update", "-qq"],
        timeout=min(300, timeout),
        env=env,
    )
    if code != 0:
        return False, f"apt-get update failed: {out}"
    code, out = _run(
        prefix + ["apt-get", "install", "-y", "-qq", *packages],
        timeout=timeout,
        env=env,
    )
    return code == 0, out


def install_spec(
    spec: ToolSpec,
    *,
    tool_paths: dict[str, str] | None = None,
    timeout_scale: int = 1,
) -> bool:
    """Install one tool if missing. Always checks PATH/config first — no install if already satisfied."""
    tp = tool_paths or {}
    if _have_tool_with_config(spec, tp):
        return True
    to = 300 * timeout_scale
    if spec.pip_package:
        ok, msg = _pip_install(spec.pip_package, timeout=max(600, to))
        if ok:
            log.info("pip installed %s", spec.key)
            prepend_user_local_bin_to_path()
            return bool(_which_any(spec.check_names))
        log.warning("pip install failed for %s: %s", spec.key, msg)
        return bool(_which_any(spec.check_names))
    if spec.go_package:
        ok, msg = _go_install(spec.go_package, timeout=max(900, to))
        if ok:
            log.info("go install ok: %s", spec.key)
            return bool(_which_any(spec.check_names))
        log.warning("go install failed for %s: %s", spec.key, msg)
        return bool(_which_any(spec.check_names))
    if spec.apt_packages:
        ok, msg = _apt_install(spec.apt_packages, timeout=max(900, to))
        if ok:
            log.info("apt installed %s: %s", spec.key, spec.apt_packages)
            return bool(_which_any(spec.check_names))
        log.warning("apt install failed for %s: %s", spec.key, msg)
    return bool(_which_any(spec.check_names))


def install_spec_respecting_config(spec: ToolSpec, tool_paths: dict[str, str]) -> bool:
    return install_spec(spec, tool_paths=tool_paths)


def ensure_tools_for_config(config: AppConfig) -> list[str]:
    """
    Install missing tools needed by discovery providers and scanner plugins.
    Returns list of tool keys still missing after attempts.
    """
    prepend_user_local_bin_to_path()
    prepend_go_bin_to_path()
    keys = required_tool_keys_for_config(
        list(config.discovery.providers),
        list(config.scanning.plugins),
    )
    log_preflight_tools(
        keys,
        config.tool_paths,
        title="Preflight: checking tools required by discovery + scanning config",
    )
    missing: list[str] = []
    for key in sorted(keys):
        spec = spec_for_key(key)
        if spec is None:
            log.debug("no installer recipe for tool key %s", key)
            continue
        if _have_tool_with_config(spec, config.tool_paths):
            continue
        log.info("installing missing tool: %s", key)
        if install_spec_respecting_config(spec, config.tool_paths):
            ok, detail = tool_check_detail(spec, config.tool_paths)
            log.info("  %-14s now available — %s", key, detail)
            continue
        missing.append(key)
    if missing:
        log.warning(
            "tools still missing after bootstrap (Debian: apt/go/pip, or set tools.* paths): %s",
            ", ".join(missing),
        )
    return missing


def install_all_supported_tools() -> int:
    """Install every tool in TOOL_SPECS (for --install-tools)."""
    if not _is_debian_family():
        log.warning(
            "This host does not look like Debian/Ubuntu; apt-based installs may be skipped. "
            "Go/pip installs still run."
        )
    prepend_user_local_bin_to_path()
    prepend_go_bin_to_path()
    all_keys = frozenset(s.key for s in TOOL_SPECS)
    log_preflight_tools(all_keys, {}, title="Preflight: checking all supported tools")
    failed: list[str] = []
    for spec in TOOL_SPECS:
        ok, detail = tool_check_detail(spec, {})
        if ok:
            log.info("skip install (already satisfied): %s — %s", spec.key, detail)
            continue
        log.info("installing (was missing): %s", spec.key)
        if not install_spec(spec, tool_paths={}):
            failed.append(spec.key)
    if failed:
        log.error("could not install: %s", ", ".join(failed))
        return 1
    log.info("all supported tools satisfied (ensure GOPATH/bin and ~/.local/bin are on PATH)")
    return 0
