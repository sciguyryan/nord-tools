#!/usr/bin/env python3
"""Read-only platform and dependency checks for Nord Tools."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from dataclasses import asdict, dataclass


MIN_PYTHON = (3, 10)
# A missing optional tool must not prevent offline policy inspection.
TOOLS = (
    ("ping", "ICMP benchmarking", False),
    ("nordvpn", "NordVPN CLI connection support", False),
    ("ip", "Linux namespace and route management", False),
    ("nft", "Linux nftables isolation", False),
    ("wg", "Future WireGuard tunnel management", False),
    ("systemctl", "Future automatic startup integration", False),
)


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    required: bool


def inspect(*, system: str | None = None, version: tuple[int, ...] | None = None) -> list[Check]:
    """Report capabilities without executing commands or modifying the host."""
    system = platform.system() if system is None else system
    version = sys.version_info[:3] if version is None else version
    supported = system == "Linux"
    checks = [
        Check("platform", "ok" if supported else "unsupported", f"{system}: only Linux is supported", True),
        Check(
            "python",
            "ok" if version >= MIN_PYTHON else "missing",
            f"Python {'.'.join(map(str, version))}; minimum {'.'.join(map(str, MIN_PYTHON))}",
            True,
        ),
    ]
    for executable, purpose, required in TOOLS:
        location = shutil.which(executable)
        checks.append(
            Check(executable, "ok" if location else "missing", f"{purpose}: {location or 'not found'}", required)
        )
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print machine-readable results")
    parser.add_argument("--strict", action="store_true", help="Also fail when optional tools are unavailable")
    args = parser.parse_args(argv)
    checks = inspect()
    if args.json:
        print(json.dumps({"checks": [asdict(check) for check in checks]}, indent=2))
    else:
        for check in checks:
            print(f"{check.status.upper():11} {check.name:12} {check.detail}")
        print("Optional tools are feature-specific; missing tools do not prevent offline planning.")
    return 2 if any(check.status != "ok" and (check.required or args.strict) for check in checks) else 0


if __name__ == "__main__":
    sys.exit(main())
