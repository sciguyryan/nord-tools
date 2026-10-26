#!/usr/bin/env python3
"""Opt-in privileged acceptance probe for disposable namespace ownership.

No host routes, DNS, firewall rules or existing namespaces are modified.
The namespace is created with a random name and retired within this process.
A failure may leave a namespace requiring manual inspection; no name-based
fallback cleanup is attempted.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nordvpn_namespace_ownership import OwnershipError, disposable_namespace  # noqa: E402


def probe(*, confirmed: bool = False) -> str:
    """Run only after explicit opt-in; return the random namespace name."""
    if not confirmed:
        raise OwnershipError("explicit --run-privileged confirmation required")
    if sys.platform != "linux" or os.geteuid() != 0:
        raise OwnershipError("requires Linux and effective root privileges")
    if shutil.which("ip") is None:
        raise OwnershipError("iproute2 'ip' executable is required")
    name = "nt-" + secrets.token_hex(8)
    print(f"Creating disposable namespace {name}; inspect /run/netns if interrupted", flush=True)
    with disposable_namespace(name) as owned:
        owned.verify()
        print(f"PASS: descriptor-bound identity verified for {name}", flush=True)
    print(f"PASS: disposable namespace retired: {name}", flush=True)
    return name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-privileged", action="store_true", help="Explicitly authorise one disposable namespace creation"
    )
    args = parser.parse_args(argv)
    try:
        probe(confirmed=args.run_privileged)
    except OwnershipError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
