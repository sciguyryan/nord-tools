#!/usr/bin/env python3
"""Opt-in, disposable network-namespace firewall feasibility probe.

This is not a VPN tunnel test. It checks whether a namespace can keep ordinary
underlay packets blocked even when its preferred (simulated tunnel) link fails.
The host's routes, DNS and firewall are never modified.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import subprocess
import sys


class ProbeError(RuntimeError):
    """A prerequisite or an isolation assertion failed."""


def commands(name: str) -> list[list[str]]:
    """Build a fixed-command probe with no user-supplied shell fragments."""
    peer = f"{name}-p"
    remote = f"{name}-r"
    return [
        ["ip", "netns", "add", name],
        ["ip", "netns", "add", remote],
        ["ip", "-n", name, "link", "set", "lo", "up"],
        ["ip", "link", "add", peer, "type", "veth", "peer", "name", "underlay"],
        ["ip", "link", "set", peer, "netns", name],
        ["ip", "link", "set", "underlay", "netns", remote],
        ["ip", "-n", remote, "addr", "add", "198.18.0.1/30", "dev", "underlay"],
        ["ip", "-n", remote, "link", "set", "underlay", "up"],
        ["ip", "-n", name, "addr", "add", "198.18.0.2/30", "dev", peer],
        ["ip", "-n", name, "link", "set", peer, "up"],
        ["ip", "-n", name, "link", "add", "tunnel-sim", "type", "dummy"],
        ["ip", "-n", name, "link", "set", "tunnel-sim", "up"],
        # A direct underlay route is essential: without it, a failed ping could
        # simply mean the dummy default route swallowed the packet.
        ["ip", "-n", name, "route", "add", "198.18.0.1/32", "dev", peer],
        ["ip", "-n", name, "route", "add", "default", "dev", "tunnel-sim"],
        ["ip", "netns", "exec", name, "nft", "-f", "-"],
    ]


FIREWALL = """table inet vpn_probe {
 chain output {
  type filter hook output priority 0; policy drop;
  oifname "lo" accept
  oifname "tunnel-sim" accept
  oifname "{underlay}" counter drop
 }
}
"""


def run(argv: list[str], *, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, input=input_text, text=True, capture_output=True, check=check)


def dropped_packets(output: str, underlay: str) -> int:
    """Read the explicit underlay-drop counter, failing on ambiguous output.

    A ping failure by itself proves little: missing routes, broken peers and
    missing capabilities can all look like a firewall working correctly.
    """
    match = re.search(
        rf'oifname "{re.escape(underlay)}" counter packets (\d+) bytes \d+ drop',
        output,
    )
    if match is None:
        raise ProbeError("Cannot verify namespace underlay-drop counter")
    return int(match.group(1))


def probe(name: str) -> None:
    """Verify underlay remains blocked before and after simulated tunnel loss."""
    created = []
    peer = f"{name}-p"
    try:
        for index, command in enumerate(commands(name)):
            # Namespace creation may succeed even when the next operation fails.
            if index in (0, 1):
                result = run(command, check=False)
                if result.returncode:
                    raise ProbeError(result.stderr.strip() or "Cannot create namespace")
                created.append(command[-1])
            else:
                run(command, input_text=FIREWALL.replace("{underlay}", peer) if command[-2:] == ["-f", "-"] else None)
        # Confirm the underlay peer is reachable from its own namespace before
        # interpreting any blocked packets as evidence of firewall enforcement.
        run(["ip", "netns", "exec", name, "ip", "route", "get", "198.18.0.1"])
        for state in ("up", "down"):
            if state == "down":
                run(["ip", "-n", name, "link", "set", "tunnel-sim", "down"])
            # The underlay peer is reachable in a second disposable namespace. A successful ping
            # would prove that the firewall permits a non-tunnel escape.
            counter_command = ["ip", "netns", "exec", name, "nft", "-a", "list", "chain", "inet", "vpn_probe", "output"]
            before = dropped_packets(run(counter_command).stdout, peer)
            result = run(["ip", "netns", "exec", name, "ping", "-n", "-c", "1", "-W", "1", "198.18.0.1"], check=False)
            if result.returncode == 0:
                raise ProbeError(f"Underlay unexpectedly reachable with simulated tunnel {state}")
            # Inspect packet counters to distinguish a firewall drop from a
            # missing route, missing ping binary or unrelated execution failure.
            if result.returncode not in (1,):
                raise ProbeError(f"Ping probe could not execute: {result.stderr.strip()}")
            after = dropped_packets(run(counter_command).stdout, peer)
            if after <= before:
                raise ProbeError(f"Underlay drop counter did not advance with simulated tunnel {state}")
            print(f"PASS: underlay firewall drop verified, simulated tunnel {state}")
    finally:
        for namespace in reversed(created):
            result = run(["ip", "netns", "del", namespace], check=False)
            if result.returncode:
                print(f"WARNING: cleanup failed for namespace {namespace}: {result.stderr.strip()}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute", action="store_true", help="Create disposable namespace (requires root, ip, nft and ping)"
    )
    args = parser.parse_args(argv)
    name = "vpnprobe-" + secrets.token_hex(4)
    if not args.execute:
        print("DRY RUN: would create an isolated namespace, veth underlay and dummy tunnel;")
        print("install namespace-only nftables output filtering, test tunnel up/down, then clean up.")
        print("No real VPN, DNS, IPv6 or host-level leak protection is tested.")
        return 0
    missing = [tool for tool in ("ip", "nft", "ping") if shutil.which(tool) is None]
    if missing:
        parser.error("Missing prerequisites: " + ", ".join(missing))
    if os.geteuid() != 0:
        parser.error("--execute requires root")
    try:
        probe(name)
    except (ProbeError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
