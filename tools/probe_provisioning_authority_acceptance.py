#!/usr/bin/env python3
"""Run the explicit, fail-fast privileged provisioning authority acceptance sequence.

Each existing probe creates its own disposable resources and retains failure
artefacts. This runner never removes those artefacts or attempts recovery after
an unsuccessful stage. It cannot certify resistance to independent privileged
network or mount administrators.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGES = (
    ("ownership preflight", "probe_ownership_preflight.py"),
    ("startup restoration", "probe_restore_startup.py"),
    ("confirmed cleanup", "probe_cleanup.py"),
    ("interrupted-operation recovery", "probe_recovery.py"),
    ("integrated restoration lifecycle matrix", "probe_startup_restoration_lifecycle.py"),
)


def run_acceptance(*, python: str = sys.executable) -> bool:
    """Stop at the first failed stage, retaining its original diagnostic output."""
    for label, filename in STAGES:
        print(f"RUN: {label}", flush=True)
        result = subprocess.run(
            [python, str(ROOT / "tools" / filename), "--run-privileged"],
            check=False,
        )
        if result.returncode != 0:
            print(f"FAIL: {label} (exit {result.returncode}); later stages not attempted", file=sys.stderr, flush=True)
            return False
        print(f"PASS: {label}", flush=True)
    print("PASS: all five privileged lifecycle acceptance stages completed", flush=True)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="run all five disposable privileged probes")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: privileged stages (in order):")
        for label, filename in STAGES:
            print(f"  {label}: {filename} --run-privileged")
        print("No privileged probes executed.")
        return 0
    if os.geteuid() != 0:
        print("FAIL: explicit privileged acceptance requires root", file=sys.stderr)
        return 2
    return 0 if run_acceptance() else 1


if __name__ == "__main__":
    raise SystemExit(main())
