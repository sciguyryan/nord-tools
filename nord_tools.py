#!/usr/bin/env python3
"""Unified command-line entry point for Nord Tools.

Commands delegate to their existing implementations to preserve established
options, output and exit codes. Experimental tools remain explicitly labelled.
"""

from __future__ import annotations

import argparse
import sys
import importlib


COMMANDS = {
    "doctor": ("nordvpn_doctor", "Check supported platform and feature-specific tools (read-only)"),
    "benchmark": ("nordvpn_benchmark", "Benchmark and rank NordVPN servers"),
    "policy": ("nordvpn_policy", "Validate policy or plan default optimisation (offline)"),
    "topology": ("nordvpn_topology", "Inspect proposed routing domains (design only)"),
    "manage": ("nordvpn_manage", "Manage saved VPN intent (offline; no live networking)"),
    "divergence": ("nordvpn_kongroo", argparse.SUPPRESS),
    "wireguard-probe": ("tools.probe_two_wireguard", "Disposable two-pair WireGuard experiment (privileged opt-in)"),
    "namespace-probe": ("tools.probe_namespace_isolation", "Disposable namespace experiment (privileged opt-in)"),
}


def main(argv: list[str] | None = None) -> int:
    """Dispatch a subcommand without changing the underlying tool's CLI."""
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", nargs="?", help="Tool to run")
    values = list(sys.argv[1:] if argv is None else argv)
    if not values or values[0] in ("-h", "--help"):
        parser.print_help()
        return 0
    args = parser.parse_args(values[:1])
    if args.command not in COMMANDS:
        parser.error(f"unknown command: {args.command}")
    remainder = values[1:]
    if args.command is None:
        parser.print_help()
        return 0

    # Import only the selected tool, keeping --help and offline commands free
    # of unnecessary networking or probe dependencies.
    module = importlib.import_module(COMMANDS[args.command][0])
    return module.main(remainder) or 0


if __name__ == "__main__":
    sys.exit(main())
