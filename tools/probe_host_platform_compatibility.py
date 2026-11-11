#!/usr/bin/env python3
"""Inspect the supported host-default deployment profile without changing networking."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nord_tools_internal.nordvpn_host_executor import (  # noqa: E402
    HostProtectionError,
    inspect_host_compatibility,
)
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, help="Validated host protection plan JSON")
    parser.add_argument("--run-privileged", action="store_true", help="perform live read-only host inspection")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: would inspect the systemd-networkd static-egress host profile and competing managers")
        print("No commands executed and no network changes made.")
        return 0
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("--run-privileged requires Linux root")
    try:
        document = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        plan = HostProtectionPlan.from_mapping(document)
        report = inspect_host_compatibility(plan)
    except (OSError, ValueError, TypeError, HostProtectionError) as exc:
        print(f"FAIL: unsupported host deployment profile: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    print("PASS: host deployment matches the supported static-egress profile", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
