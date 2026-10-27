#!/usr/bin/env python3
"""Disposable dual-stack DNS route-confinement feasibility probe.

The tunnel is a dummy device, not WireGuard. This tests route selection and
absence of an underlay fallback, not successful DNS delivery or real VPN leaks.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import subprocess
import sys

from probe_namespace_isolation import FIREWALL, commands, run, underlay_interface


class RouteProbeError(RuntimeError):
    """The disposable routing assertion or a prerequisite failed."""


# Targets must not overlap the directly connected underlay networks.
DNS_TARGETS = (("ipv4", "198.18.0.53", "-4"), ("ipv6", "fd42:5::53", "-6"))


def route_device(output: str) -> str | None:
    """Extract a single kernel-reported output device, refusing ambiguity."""
    devices = re.findall(r"(?:^|\s)dev\s+(\S+)", output)
    return devices[0] if len(devices) == 1 else None


def assert_dns_route(name: str, family: str, address: str, flag: str, *, tunnel_up: bool, peer: str) -> None:
    """Require tunnel routing when up and no underlay fallback when down."""
    result = run(["ip", "netns", "exec", name, "ip", flag, "route", "get", address], check=False)
    if tunnel_up:
        if result.returncode or route_device(result.stdout) != "tunnel-sim":
            raise RouteProbeError(
                f"{family} DNS route does not select simulated tunnel: {result.stdout} {result.stderr}"
            )
    elif result.returncode != 0:
        if "unreachable" not in result.stderr.lower():
            raise RouteProbeError(f"{family} DNS route lookup failed unexpectedly: {result.stderr}")
    else:
        device = route_device(result.stdout)
        # Even a route through the downed dummy device is unacceptable as
        # positive connectivity evidence; underlay fallback is the leak risk.
        if device is None or device == peer or device != "tunnel-sim":
            raise RouteProbeError(f"{family} DNS route unexpectedly falls back or is ambiguous: {result.stdout}")
    print(f"PASS: {family} DNS route {'selects simulated tunnel' if tunnel_up else 'has no underlay fallback'}")


def probe(name: str) -> None:
    """Create only disposable namespaces and retire them on every exit path."""
    created: list[str] = []
    peer = underlay_interface(name)
    try:
        for index, command in enumerate(commands(name)):
            if index in (0, 1):
                result = run(command, check=False)
                if result.returncode:
                    raise RouteProbeError(result.stderr.strip() or "Cannot create namespace")
                created.append(command[-1])
            else:
                run(command, input_text=FIREWALL.replace("{underlay}", peer) if command[-2:] == ["-f", "-"] else None)
        # The shared firewall harness installs only an IPv4 default route.
        # Install the IPv6 simulated-tunnel default explicitly for this route probe.
        run(["ip", "-n", name, "-6", "route", "add", "default", "dev", "tunnel-sim"])
        for family, address, flag in DNS_TARGETS:
            assert_dns_route(name, family, address, flag, tunnel_up=True, peer=peer)
        run(["ip", "-n", name, "link", "set", "tunnel-sim", "down"])
        for family, address, flag in DNS_TARGETS:
            assert_dns_route(name, family, address, flag, tunnel_up=False, peer=peer)
    finally:
        for namespace in reversed(created):
            result = run(["ip", "netns", "del", namespace], check=False)
            if result.returncode:
                print(f"WARNING: cleanup failed for namespace {namespace}: {result.stderr.strip()}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Run disposable privileged route checks")
    args = parser.parse_args(argv)
    if not args.execute:
        print("DRY RUN: would verify IPv4/IPv6 DNS route selection and tunnel-loss fallback")
        print("in disposable namespaces with a simulated tunnel; no real DNS or VPN is tested.")
        return 0
    missing = [tool for tool in ("ip", "nft") if shutil.which(tool) is None]
    if missing:
        parser.error("Missing prerequisites: " + ", ".join(missing))
    if os.geteuid() != 0:
        parser.error("--execute requires root")
    try:
        probe("vpnprobe-" + secrets.token_hex(4))
    except (RouteProbeError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
