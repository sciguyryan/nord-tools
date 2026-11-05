#!/usr/bin/env python3
"""Run later-boundary interruption recovery probes with explicit root approval.

Each probe uses independent disposable resources and retains diagnostic evidence
on failure. A failure stops the matrix; no automatic cross-probe cleanup runs.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CHECKPOINTS = ("underlay", "wireguard", "routing")


def run_acceptance(*, python: str = sys.executable) -> bool:
    for checkpoint in CHECKPOINTS:
        print(f"RUN: interruption after {checkpoint}", flush=True)
        try:
            result = subprocess.run(
                [python, str(ROOT / "tools" / "probe_recovery.py"), "--checkpoint", checkpoint, "--run-privileged"],
                check=False,
            )
        except OSError as exc:
            print(f"FAIL: {checkpoint}: {exc}; later checkpoints not attempted", file=sys.stderr, flush=True)
            return False
        if result.returncode:
            print(
                f"FAIL: {checkpoint} (exit {result.returncode}); later checkpoints not attempted",
                file=sys.stderr,
                flush=True,
            )
            return False
        print(f"PASS: {checkpoint}", flush=True)
    print("PASS: all later provisioning interruption checkpoints completed", flush=True)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="authorise disposable kernel interruption probes")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: later interruption checkpoints: " + ", ".join(CHECKPOINTS))
        print("No privileged probes executed.")
        return 0
    if os.geteuid() != 0:
        print("FAIL: privileged recovery acceptance requires root", file=sys.stderr)
        return 2
    return 0 if run_acceptance() else 1


if __name__ == "__main__":
    raise SystemExit(main())
