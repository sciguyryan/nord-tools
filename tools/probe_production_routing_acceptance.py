#!/usr/bin/env python3
"""Fail-fast privileged acceptance for production routing and real WireGuard.

The stages have distinct evidence scopes: production lifecycle authority,
real encrypted packet exchange and host integrity, and disposable dual-stack
firewall/route checks. Passing is not a production DNS-leak certification.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGES = (
    ("supported network platform and readback contract", "probe_platform_compatibility.py", "--run-privileged"),
    ("production provisioning and restoration", "probe_provisioning_integration.py", "--run-privileged"),
    ("real WireGuard exchange, loss and host integrity", "probe_wireguard_host_integrity.py", "--execute"),
    ("dual-stack firewall and no-fallback packet policy", "probe_dual_stack_packet_policy.py", "--run-privileged"),
)


def run_acceptance(*, python: str = sys.executable) -> bool:
    """Stop immediately on a failed stage, preserving the probe's diagnostics."""
    for label, script, argument in STAGES:
        print(f"RUN: {label}", flush=True)
        try:
            result = subprocess.run([python, str(ROOT / "tools" / script), argument], check=False)
        except OSError as exc:
            print(f"FAIL: {label}: {exc}; later stages not attempted", file=sys.stderr, flush=True)
            return False
        if result.returncode:
            print(f"FAIL: {label} (exit {result.returncode}); later stages not attempted", file=sys.stderr, flush=True)
            return False
        print(f"PASS: {label}", flush=True)
    print("PASS: integrated production routing acceptance stages (within their documented evidence scopes)", flush=True)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="authorise disposable privileged probes")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: integrated privileged stages:")
        for label, script, argument in STAGES:
            print(f"  {label}: {script} {argument}")
        print("No privileged probes executed.")
        return 0
    if os.geteuid() != 0:
        parser.error("--run-privileged requires root")
    return 0 if run_acceptance() else 1


if __name__ == "__main__":
    raise SystemExit(main())
