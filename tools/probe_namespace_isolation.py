#!/usr/bin/env python3
"""Opt-in, disposable network-namespace firewall feasibility probe.

This is not a VPN tunnel test. It checks whether a namespace can keep ordinary
underlay packets blocked even when its preferred (simulated tunnel) link fails.
The host's routes, DNS and firewall are never modified.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import sys


class ProbeError(RuntimeError):
    """A prerequisite or an isolation assertion failed."""


def underlay_interface(name: str) -> str:
    """Derive a stable, namespace-specific interface name within Linux IFNAMSIZ."""
    return "vp" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]


def commands(name: str) -> list[list[str]]:
    """Build a fixed-command probe with no user-supplied shell fragments."""
    peer = underlay_interface(name)
    remote = f"{name}-r"
    return [
        ["ip", "netns", "add", name],
        ["ip", "netns", "add", remote],
        ["ip", "-n", name, "link", "set", "lo", "up"],
        ["ip", "link", "add", peer, "type", "veth", "peer", "name", "underlay"],
        ["ip", "link", "set", peer, "netns", name],
        ["ip", "link", "set", "underlay", "netns", remote],
        ["ip", "-n", remote, "addr", "add", "198.18.0.1/30", "dev", "underlay"],
        ["ip", "-n", remote, "-6", "addr", "add", "fd42:4::1/64", "dev", "underlay"],
        ["ip", "-n", remote, "link", "set", "underlay", "up"],
        ["ip", "-n", name, "addr", "add", "198.18.0.2/30", "dev", peer],
        ["ip", "-n", name, "-6", "addr", "add", "fd42:4::2/64", "dev", peer],
        ["ip", "-n", name, "link", "set", peer, "up"],
        ["ip", "-n", name, "link", "add", "tunnel-sim", "type", "dummy"],
        ["ip", "-n", name, "link", "set", "tunnel-sim", "up"],
        # A direct underlay route is essential: without it, a failed ping could
        # simply mean the dummy default route swallowed the packet.
        ["ip", "-n", name, "route", "add", "198.18.0.1/32", "dev", peer],
        ["ip", "-n", name, "-6", "route", "add", "fd42:4::1/128", "dev", peer],
        ["ip", "-n", name, "route", "add", "default", "dev", "tunnel-sim"],
        ["ip", "netns", "exec", name, "nft", "-f", "-"],
    ]


FIREWALL = """table inet vpn_probe {
 chain output {
  type filter hook output priority 0; policy drop;
  oifname "lo" accept
  oifname "tunnel-sim" accept
  meta nfproto ipv4 oifname "{underlay}" udp dport 53 counter drop comment "dns4udp"
  meta nfproto ipv4 oifname "{underlay}" tcp dport 53 counter drop comment "dns4tcp"
  meta nfproto ipv6 oifname "{underlay}" udp dport 53 counter drop comment "dns6udp"
  meta nfproto ipv6 oifname "{underlay}" tcp dport 53 counter drop comment "dns6tcp"
  meta nfproto ipv4 oifname "{underlay}" counter drop
  meta nfproto ipv6 oifname "{underlay}" counter drop
 }
}
"""


def run(argv: list[str], *, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, input=input_text, text=True, capture_output=True, check=check)


def dropped_packets(output: str, underlay: str, family: str = "ipv4") -> int:
    """Read the explicit underlay-drop counter, failing on ambiguous output.

    A ping failure by itself proves little: missing routes, broken peers and
    missing capabilities can all look like a firewall working correctly.
    """
    if family not in ("ipv4", "ipv6"):
        raise ProbeError("Unsupported packet family")
    match = re.search(
        rf'meta nfproto {family} oifname "{re.escape(underlay)}" counter packets (\d+) bytes \d+ drop',
        output,
    )
    if match is None:
        raise ProbeError("Cannot verify namespace underlay-drop counter")
    return int(match.group(1))


def dns_drop_packets(output: str, family: str, transport: str) -> int:
    """Require an unambiguous named DNS-drop rule in the nftables output."""
    if family not in ("ipv4", "ipv6") or transport not in ("udp", "tcp"):
        raise ProbeError("Unsupported DNS packet family or transport")
    label = f"dns{4 if family == 'ipv4' else 6}{transport}"
    matches = re.findall(rf'{transport} dport 53 counter packets (\d+) bytes \d+ drop comment "{label}"', output)
    if len(matches) != 1:
        raise ProbeError(f"Cannot verify unique {label} firewall drop counter")
    return int(matches[0])


def dns_attempt_command(name: str, family: str, transport: str, target: str) -> list[str]:
    """Send one synthetic DNS packet without using the host resolver or DNS settings."""
    if family not in ("ipv4", "ipv6") or transport not in ("udp", "tcp"):
        raise ProbeError("Unsupported DNS packet family or transport")
    # An outbound UDP send can succeed even when nftables drops the packet.
    # The per-rule kernel counter, not the socket return code, is the evidence.
    # nftables may reject a local UDP send synchronously with EPERM. This is
    # expected only when the matching kernel drop counter advances afterwards.
    # Exit 77 distinguishes this result from a successful socket operation.
    code = (
        "import errno, socket, sys\n"
        "family = socket.AF_INET6 if sys.argv[1] == 'ipv6' else socket.AF_INET\n"
        "kind = socket.SOCK_DGRAM if sys.argv[2] == 'udp' else socket.SOCK_STREAM\n"
        "sock = socket.socket(family, kind)\n"
        "sock.setblocking(False)\n"
        "target = (sys.argv[3], 53)\n"
        "try:\n"
        "    sock.sendto(b'\\x00' * 12, target) if kind == socket.SOCK_DGRAM else sock.connect_ex(target)\n"
        "except OSError as exc:\n"
        "    if exc.errno != errno.EPERM:\n"
        "        raise\n"
        "    sys.exit(77)\n"
    )
    return ["ip", "netns", "exec", name, sys.executable, "-c", code, family, transport, target]


def probe(name: str) -> None:
    """Verify underlay remains blocked before and after simulated tunnel loss."""
    created = []
    peer = underlay_interface(name)
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
        run(["ip", "netns", "exec", name, "ip", "-6", "route", "get", "fd42:4::1"])
        for state in ("up", "down"):
            if state == "down":
                run(["ip", "-n", name, "link", "set", "tunnel-sim", "down"])
            counter_command = ["ip", "netns", "exec", name, "nft", "-a", "list", "chain", "inet", "vpn_probe", "output"]
            for family, target, flag in (("ipv4", "198.18.0.1", "-4"), ("ipv6", "fd42:4::1", "-6")):
                before = dropped_packets(run(counter_command).stdout, peer, family)
                result = run(
                    ["ip", "netns", "exec", name, "ping", flag, "-n", "-c", "1", "-W", "1", target],
                    check=False,
                )
                if result.returncode == 0:
                    raise ProbeError(f"{family} underlay unexpectedly reachable with simulated tunnel {state}")
                if result.returncode != 1:
                    raise ProbeError(f"{family} ping probe could not execute: {result.stderr.strip()}")
                after = dropped_packets(run(counter_command).stdout, peer, family)
                if after <= before:
                    raise ProbeError(f"{family} underlay drop counter did not advance with simulated tunnel {state}")
                print(f"PASS: {family} underlay firewall drop verified, simulated tunnel {state}")
                for transport in ("udp", "tcp"):
                    before_dns = dns_drop_packets(run(counter_command).stdout, family, transport)
                    attempt = run(dns_attempt_command(name, family, transport, target), check=False)
                    if attempt.returncode not in (0, 77):
                        raise ProbeError(f"{family} {transport} DNS packet generator failed: {attempt.stderr.strip()}")
                    after_dns = dns_drop_packets(run(counter_command).stdout, family, transport)
                    if after_dns <= before_dns:
                        raise ProbeError(f"{family} {transport} DNS drop counter did not advance with tunnel {state}")
                    print(f"PASS: {family} {transport} DNS underlay drop verified, simulated tunnel {state}")
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
        print("Tests synthetic IPv4/IPv6 UDP/TCP DNS underlay drops, not resolver confinement or real VPN DNS.")
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
