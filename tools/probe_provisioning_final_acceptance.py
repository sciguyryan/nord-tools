#!/usr/bin/env python3
"""Run the complete disposable provisioning acceptance matrix.

Each child owns its resources and diagnostic evidence. On failure this runner
stops immediately and never attempts cleanup on another probe's behalf.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGES = (
    ("production integration", "probe_provisioning_integration.py"),
    ("later interruption recovery", "probe_later_recovery.py"),
)


def run_acceptance(*, python: str = sys.executable) -> bool:
    """Delegate to established acceptance probes without acquiring new authority."""
    for label, filename in STAGES:
        print(f"RUN: {label}", flush=True)
        try:
            result = subprocess.run(
                [python, str(ROOT / "tools" / filename), "--run-privileged"],
                check=False,
            )
        except OSError as exc:
            print(f"FAIL: {label}: {exc}; subsequent stages not attempted", file=sys.stderr, flush=True)
            return False
        if result.returncode:
            print(
                f"FAIL: {label} (exit {result.returncode}); subsequent stages not attempted",
                file=sys.stderr,
                flush=True,
            )
            return False
        print(f"PASS: {label}", flush=True)
    print("PASS: complete provisioning acceptance matrix", flush=True)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="authorise disposable privileged probes")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: complete provisioning acceptance matrix:")
        for label, filename in STAGES:
            print(f"  {label}: {filename} --run-privileged")
        print("No privileged probes executed.")
        return 0
    if os.geteuid() != 0:
        print("FAIL: complete provisioning acceptance requires root", file=sys.stderr)
        return 2
    return 0 if run_acceptance() else 1


if __name__ == "__main__":
    raise SystemExit(main())
