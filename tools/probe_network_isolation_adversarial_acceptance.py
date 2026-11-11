#!/usr/bin/env python3
"""Consolidated privileged fail-closed and host-integrity acceptance.

Every stage uses its own disposable resources. The runner does not assume
ownership of child resources or attempt cleanup following a failed stage.
The outer host-state comparison runs even when a child stage fails.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.probe_wireguard_host_integrity import observe, verify  # noqa: E402

STAGES = (
    (
        "production provisioning, real WireGuard and dual-stack routing",
        "probe_production_routing_acceptance.py",
        "--run-privileged",
    ),
    ("late-stage interrupted provisioning and rollback", "probe_later_recovery.py", "--run-privileged"),
    ("cooperating-process lock and substitution refusal", "probe_lifecycle_lock_concurrency.py", "--run"),
)


def run_acceptance(*, python: str = sys.executable) -> bool:
    """Fail closed on any probe or host-state observation failure."""
    try:
        before = observe()
    except (OSError, RuntimeError) as exc:
        print(f"FAIL: cannot establish initial host-state evidence: {exc}", file=sys.stderr, flush=True)
        return False

    failure: str | None = None
    try:
        for label, filename, argument in STAGES:
            print(f"RUN: {label}", flush=True)
            try:
                result = subprocess.run([python, str(ROOT / "tools" / filename), argument], check=False)
            except OSError as exc:
                failure = f"{label}: {exc}"
                break
            if result.returncode:
                failure = f"{label} (exit {result.returncode})"
                break
            print(f"PASS: {label}", flush=True)
    finally:
        try:
            verify(before, observe())
        except (OSError, RuntimeError) as exc:
            print(f"FAIL: host integrity after acceptance: {exc}", file=sys.stderr, flush=True)
            failure = f"{failure}; host integrity failed" if failure else "host integrity failed"

    if failure:
        print(f"FAIL: {failure}; subsequent stages not attempted", file=sys.stderr, flush=True)
        return False
    print("PASS: network isolation adversarial acceptance within the documented evidence boundaries", flush=True)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="authorise all disposable privileged probes")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: network isolation adversarial acceptance stages:")
        for label, filename, argument in STAGES:
            print(f"  {label}: {filename} {argument}")
        print("No host observations or privileged probes executed.")
        return 0
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("--run-privileged requires Linux root")
    return 0 if run_acceptance() else 1


if __name__ == "__main__":
    raise SystemExit(main())
