#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _bootstrap_path() -> None:
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))


def main() -> int:
    _bootstrap_path()

    from recon.core.config_loader import load_config
    from recon.core.engine import PipelineEngine
    from recon.core.logger import setup_logging

    parser = argparse.ArgumentParser(
        description="AutoRecon — reconnaissance and automated assessment pipeline",
    )
    parser.add_argument("--domain", "-d", help="Target domain or hostname (overrides config)")
    parser.add_argument(
        "--single-domain",
        action="store_true",
        help="Scan only this host/IP: skip subdomain discovery (crt.sh, subfinder, …)",
    )
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=None,
        help="Optional YAML/JSON overrides; defaults already use real crt.sh+subfinder+wayback and httpx+wafw00f+nuclei",
    )
    parser.add_argument(
        "--scan",
        choices=("full", "quick", "none"),
        default="full",
        help="Scan profile: full (parallel if configured), quick (sequential), none",
    )
    parser.add_argument(
        "--execution",
        choices=("sequential", "async"),
        default=None,
        help="Override execution.mode from config",
    )
    parser.add_argument(
        "--install-tools",
        action="store_true",
        help="Install all supported external tools (Go, pip, apt on Debian/Ubuntu) then exit",
    )
    parser.add_argument(
        "--no-auto-tools",
        action="store_true",
        help="Disable automatic tool install even if bootstrap.auto_install is true",
    )
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Only check required tools (PATH / config); print status and exit 0 if all found, 1 if any missing",
    )
    args = parser.parse_args()

    cli_patch: dict = {}
    if args.domain:
        cli_patch["domain"] = args.domain
    if args.single_domain:
        cli_patch.setdefault("discovery", {})["single_target_mode"] = True
    if args.execution:
        cli_patch.setdefault("execution", {})["mode"] = args.execution

    config = load_config(args.config, cli_overrides=cli_patch or None)
    setup_logging(config.log_level, config.log_json)

    if args.install_tools:
        from recon.bootstrap.installer import install_all_supported_tools

        return install_all_supported_tools()

    if args.check_tools:
        from recon.bootstrap.installer import (
            check_tools_for_config,
            prepend_go_bin_to_path,
            prepend_user_local_bin_to_path,
        )

        prepend_user_local_bin_to_path()
        prepend_go_bin_to_path()
        all_ok, results = check_tools_for_config(config)
        if not results:
            print("No external CLI tools required for current discovery.plugins + scanning.plugins.")
            return 0
        for key in sorted(results):
            ok, detail = results[key]
            line = "OK " if ok else "NO "
            print(f"{line}{key}: {detail}")
        return 0 if all_ok else 1

    if args.no_auto_tools:
        config.bootstrap.auto_install = False

    from recon.bootstrap.installer import (
        prepend_go_bin_to_path,
        prepend_user_local_bin_to_path,
    )

    prepend_user_local_bin_to_path()
    prepend_go_bin_to_path()
    if config.bootstrap.auto_install:
        from recon.bootstrap.installer import ensure_tools_for_config

        ensure_tools_for_config(config)
        prepend_go_bin_to_path()

    if args.scan == "quick":
        config.scanning.parallel_workers = 1
        config.execution.mode = "sequential"

    engine = PipelineEngine(config)
    domain = args.domain or config.domain
    result = engine.run(domain=domain, scan_profile=args.scan)

    if result.errors:
        for e in result.errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(
        f"Run {result.run_id}: {len(result.assets)} assets, "
        f"{len(result.findings)} findings → {config.storage.output_dir}/"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
