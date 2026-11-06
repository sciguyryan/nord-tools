#!/usr/bin/env python3
"""Run disposable dual-stack firewall and route acceptance checks.

The endpoint probe exercises the production isolation policy in disposable
namespaces. The route probe uses a simulated tunnel. These checks do not prove
real WireGuard packet confinement or DNS resolver safety.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGES = (
    ("IPv4/IPv6 endpoint exception and underlay drop", "probe_endpoint_exception.py"),
    ("IPv4/IPv6 tunnel routing and loss of tunnel", "probe_dns_route_confinement.py"),
)


def run_acceptance(*, python: str = sys.executable) -> bool:
    """Run each independent disposable check, stopping on the first failure."""
    for description, script in STAGES:
        print(f"RUN: {description}", flush=True)
        try:
            result = subprocess.run([python, str(ROOT / "tools" / script), "--execute"], check=False)
        except OSError as exc:
            print(f"FAIL: {description}: {exc}", file=sys.stderr, flush=True)
            return False
        if result.returncode:
            print(f"FAIL: {description} (exit {result.returncode})", file=sys.stderr, flush=True)
            return False
        print(f"PASS: {description}", flush=True)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="run disposable kernel packet checks")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: disposable firewall and route acceptance stages:")
        for description, script in STAGES:
            print(f"  {description}: {script} --execute")
        print("No kernel resources created.")
        return 0
    if os.geteuid() != 0:
        parser.error("--run-privileged requires root")
    return 0 if run_acceptance() else 1


if __name__ == "__main__":
    raise SystemExit(main())
