#!/usr/bin/env python3
"""Opt-in privileged smoke test for descriptor-bound disposable WireGuard configuration.

Creates one named network namespace and a WireGuard interface inside it. No
host routes, DNS settings, firewall rules or existing VPNs are changed.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nord_tools_internal.nordvpn_namespace_ownership import OwnershipError, disposable_namespace
from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification
from nord_tools_internal.nordvpn_wireguard_session import SessionError, configure_disposable_wireguard


class ProbeError(RuntimeError):
    """The disposable configuration probe failed or could not verify its result."""


def command(*argv: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(argv, input=input_data, capture_output=True, check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError("required WireGuard command could not complete") from exc
    if result.returncode:
        raise ProbeError("required WireGuard command failed")
    return result.stdout.strip()


def run_probe() -> str:
    """Configure one disposable interface and verify its kernel peer state."""
    if os.geteuid() != 0:
        raise ProbeError("root privileges are required")
    for binary in ("ip", "wg"):
        if shutil.which(binary) is None:
            raise ProbeError(f"missing prerequisite: {binary}")

    namespace = f"nt-{secrets.token_hex(8)}"
    interface = f"ntwg{secrets.token_hex(4)}"
    private_key = command("wg", "genkey")
    peer_private_key = command("wg", "genkey")
    public_key = command("wg", "pubkey", input_data=private_key).decode("ascii")
    peer_public_key = command("wg", "pubkey", input_data=peer_private_key).decode("ascii")
    spec = TunnelSpecification(
        namespace, interface, peer_public_key, "198.51.100.2", 51820, "10.213.240.2/32", ("10.213.240.1/32",)
    )
    # Avoid persistent key files. The key enters the configurator through a pipe.
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, private_key)
    finally:
        os.close(write_fd)
    try:
        print(f"Creating disposable namespace {namespace}; inspect /run/netns if interrupted", flush=True)
        with disposable_namespace(namespace) as owned:
            configure_disposable_wireguard(spec, owned, read_fd)
            owned.verify()
            actual_key = command("ip", "netns", "exec", namespace, "wg", "show", interface, "public-key").decode(
                "ascii"
            )
            actual_peers = (
                command("ip", "netns", "exec", namespace, "wg", "show", interface, "peers").decode("ascii").splitlines()
            )
            if actual_key != public_key or actual_peers != [peer_public_key]:
                raise ProbeError("kernel WireGuard configuration differs from requested configuration")
            print(f"PASS: disposable WireGuard interface configured and verified in {namespace}", flush=True)
    finally:
        os.close(read_fd)
    print(f"PASS: disposable namespace retired: {namespace}", flush=True)
    return namespace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-privileged", action="store_true", help="explicitly authorise a disposable privileged test"
    )
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print(
            "DRY RUN: would create one disposable namespace, configure a WireGuard interface, verify its peer and retire the namespace. No changes made."
        )
        return 0
    try:
        run_probe()
    except (ProbeError, OwnershipError, SessionError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
