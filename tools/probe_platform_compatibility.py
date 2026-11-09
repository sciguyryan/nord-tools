#!/usr/bin/env python3
"""Report the accepted production network platform without changing it."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nord_tools_internal.nordvpn_platform_compat import (  # noqa: E402
    PlatformCompatibilityError,
    verify_supported_network_platform,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="inspect the live privileged platform")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: would verify accepted kernel, network-tool JSON and namespace resolver semantics")
        print("No commands executed and no network changes made.")
        return 0
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("--run-privileged requires Linux root")
    try:
        report = verify_supported_network_platform()
    except PlatformCompatibilityError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    print("PASS: production network platform matches the accepted readback contract", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
