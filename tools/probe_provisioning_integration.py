#!/usr/bin/env python3
"""Run the fail-fast production provisioning integration acceptance matrix.

Each stage owns disposable resources and retains its own failure evidence. This
runner neither cleans up a failed stage nor changes host routing or DNS. It
checks the cooperating-process ownership model, not hostile root mutation.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGES = (
    ("production authority and restoration", "probe_provisioning_authority_acceptance.py", ("--run-privileged",)),
    ("independent named-profile retirement", "probe_selected_profile_retirement.py", ("--run-privileged",)),
    ("isolated allocation and lease retirement", "probe_isolated_consumer_retirement.py", ("--run-privileged",)),
    ("interruption after durable namespace binding", "probe_recovery.py", ("--after-binding", "--run-privileged")),
    (
        "real WireGuard dual-stack DNS and firewall confinement",
        "probe_wireguard_dns_acceptance.py",
        ("--run-privileged",),
    ),
)


def run_acceptance(*, python: str = sys.executable) -> bool:
    """Stop on the first failure without masking its diagnostic output."""
    for label, filename, arguments in STAGES:
        print(f"RUN: {label}", flush=True)
        try:
            result = subprocess.run(
                [python, str(ROOT / "tools" / filename), *arguments],
                check=False,
            )
        except OSError as exc:
            print(f"FAIL: {label}: {exc}; later stages not attempted", file=sys.stderr, flush=True)
            return False
        if result.returncode:
            print(
                f"FAIL: {label} (exit {result.returncode}); later stages not attempted",
                file=sys.stderr,
                flush=True,
            )
            return False
        print(f"PASS: {label}", flush=True)
    print(f"PASS: all {len(STAGES)} production provisioning integration stages completed", flush=True)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="run disposable privileged integration probes")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: privileged integration stages (in order):")
        for label, filename, arguments in STAGES:
            print(f"  {label}: {filename} {' '.join(arguments)}")
        print("No privileged probes executed.")
        return 0
    if os.geteuid() != 0:
        print("FAIL: privileged integration acceptance requires root", file=sys.stderr)
        return 2
    return 0 if run_acceptance() else 1


if __name__ == "__main__":
    raise SystemExit(main())
