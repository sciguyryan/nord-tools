#!/usr/bin/env python3
"""Consolidated privileged application routing and lifecycle acceptance.

Each child probe owns its disposable resources. Host network configuration is
checked before and after the entire matrix, including failed child stages.
This does not claim desktop compatibility, which requires separate platform
evidence.
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
    ("registered direct routing and VPN fallback refusal", "probe_application_routing_modes.py", True),
    ("production registered VPN-bound launch gate", "probe_live_tunnel_replacement.py", True),
    ("concurrent shared, isolated and direct application lifecycle", "probe_concurrent_application_lifecycle.py", True),
    (
        "concurrent registered application packet confinement",
        "probe_registered_application_confinement.py",
        True,
    ),
    ("production provisioning and ownership lifecycle", "probe_provisioning_integration.py", False),
    ("interrupted provisioning and verified recovery", "probe_later_recovery.py", False),
    ("cooperating-process lifecycle lock refusal", "probe_lifecycle_lock_concurrency.py", False),
)
SHARED_STAGES = {
    "probe_provisioning_integration.py",
    "probe_later_recovery.py",
    "probe_lifecycle_lock_concurrency.py",
}


def run_acceptance(
    uid: int,
    gid: int,
    *,
    python: str = sys.executable,
    application_stages_only: bool = False,
) -> bool:
    """Run the requested stage set, refusing success on any failure or host drift."""
    try:
        before = observe()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"FAIL: cannot establish host baseline: {exc}", file=sys.stderr, flush=True)
        return False
    failure: str | None = None
    try:
        for label, filename, needs_identity in STAGES:
            if application_stages_only and filename in SHARED_STAGES:
                continue
            arguments = [python, str(ROOT / "tools" / filename)]
            arguments.append("--run" if filename == "probe_lifecycle_lock_concurrency.py" else "--run-privileged")
            if needs_identity:
                arguments.extend(("--uid", str(uid), "--gid", str(gid)))
            print(f"RUN: {label}", flush=True)
            try:
                result = subprocess.run(arguments, check=False)
            except OSError as exc:
                failure = f"{label}: {exc}"
                break
            if result.returncode != 0:
                failure = f"{label} (exit {result.returncode})"
                break
            print(f"PASS: {label}", flush=True)
    finally:
        try:
            verify(before, observe())
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"FAIL: host integrity: {exc}", file=sys.stderr, flush=True)
            failure = f"{failure}; host integrity" if failure else "host integrity"
    if failure:
        print(f"FAIL: {failure}; later stages not attempted", file=sys.stderr, flush=True)
        return False
    scope = "application-specific" if application_stages_only else "application routing and lifecycle"
    print(f"PASS: {scope} acceptance within documented boundaries", flush=True)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true")
    parser.add_argument(
        "--application-stages-only",
        action="store_true",
        help="run only the application-specific subset for composition by the acceptance manager",
    )
    parser.add_argument("--uid", type=int, help="UID of an existing non-root test account")
    parser.add_argument("--gid", type=int, help="GID of an existing non-root test account")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        scope = "application-specific" if args.application_stages_only else "application routing and lifecycle"
        print(f"DRY RUN: {scope} acceptance")
        for label, filename, _ in STAGES:
            if args.application_stages_only and filename in SHARED_STAGES:
                continue
            print(f"  {label}: {filename}")
        return 0
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or args.uid is None
        or args.gid is None
        or args.uid <= 0
        or args.gid <= 0
    ):
        parser.error("Linux root and explicit non-root --uid/--gid are required")
    return 0 if run_acceptance(args.uid, args.gid, application_stages_only=args.application_stages_only) else 1


if __name__ == "__main__":
    raise SystemExit(main())
