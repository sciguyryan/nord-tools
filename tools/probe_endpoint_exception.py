#!/usr/bin/env python3
"""Disposable kernel-counter probe for narrowly scoped UDP endpoint exceptions.

No WireGuard, provider endpoint, host firewall, or host DNS is modified.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nord_tools_internal.nordvpn_failclosed_policy import NamespaceIsolationPolicy  # noqa: E402
from probe_namespace_isolation import commands, run, underlay_interface


class EndpointProbeError(RuntimeError):
    """The kernel did not demonstrate the expected endpoint isolation."""


ENDPOINTS = (("ipv4", "198.18.0.1", 51820), ("ipv6", "fd42:4::1", 51820))


def probe_rules(peer: str, address: str, port: int) -> str:
    """Add independent counters to the production candidate for test evidence."""
    candidate = NamespaceIsolationPolicy("tunnel-sim", peer, address, port).render_nft()
    marker = f"udp dport {port} accept"
    if candidate.count(marker) != 1:
        raise EndpointProbeError("Cannot identify unique endpoint exception")
    candidate = candidate.replace(marker, f'udp dport {port} counter accept comment "endpoint-allow"')
    candidate = candidate.replace("  }\n}", f'    oifname "{peer}" counter drop comment "underlay-deny"\n  }}\n}}')
    return candidate


def counter(output: str, label: str) -> int:
    """Reject missing or ambiguous nftables counters."""
    if label not in ("endpoint-allow", "underlay-deny"):
        raise EndpointProbeError("Unknown counter label")
    values = re.findall(rf'counter packets (\d+) bytes \d+ (?:accept|drop) comment "{label}"', output)
    if len(values) != 1:
        raise EndpointProbeError(f"Missing or ambiguous {label} counter")
    return int(values[0])


def packet_command(name: str, family: str, target: str, port: int) -> list[str]:
    """Attempt a single numeric-address UDP datagram without resolver access."""
    code = (
        "import errno,socket,sys\n"
        "s=socket.socket(socket.AF_INET6 if sys.argv[1]=='ipv6' else socket.AF_INET,socket.SOCK_DGRAM)\n"
        "try: s.sendto(b'probe', (sys.argv[2],int(sys.argv[3])))\n"
        "except OSError as e:\n"
        " if e.errno!=errno.EPERM: raise\n"
        " sys.exit(77)\n"
    )
    return ["ip", "netns", "exec", name, sys.executable, "-c", code, family, target, str(port)]


def probe(name: str) -> None:
    """Test allowed and denied underlay packets in disposable namespaces."""
    created: list[str] = []
    peer = underlay_interface(name)
    try:
        setup = commands(name)
        for index, command in enumerate(setup):
            if index in (0, 1):
                result = run(command, check=False)
                if result.returncode:
                    raise EndpointProbeError(result.stderr.strip() or "Cannot create namespace")
                created.append(command[-1])
            elif command[-2:] != ["-f", "-"]:
                run(command)
        for family, address, port in ENDPOINTS:
            # Flush only our disposable namespace's test table, never host rules.
            run(["ip", "netns", "exec", name, "nft", "delete", "table", "inet", "nord_tools_isolation"], check=False)
            run(["ip", "netns", "exec", name, "nft", "-f", "-"], input_text=probe_rules(peer, address, port))
            query = ["ip", "netns", "exec", name, "nft", "list", "chain", "inet", "nord_tools_isolation", "output"]
            for label, target, target_port in (
                ("endpoint-allow", address, port),
                ("underlay-deny", address, port + 1),
            ):
                before = counter(run(query).stdout, label)
                result = run(packet_command(name, family, target, target_port), check=False)
                if result.returncode not in (0, 77):
                    raise EndpointProbeError(f"{family} UDP packet generator failed: {result.stderr.strip()}")
                after = counter(run(query).stdout, label)
                if after <= before:
                    raise EndpointProbeError(f"{family} {label} counter did not advance")
                print(
                    f"PASS: {family} {'endpoint UDP exception' if label == 'endpoint-allow' else 'unrelated UDP underlay drop'} verified"
                )
    finally:
        for namespace in reversed(created):
            result = run(["ip", "netns", "del", namespace], check=False)
            if result.returncode:
                print(f"WARNING: namespace cleanup failed for {namespace}: {result.stderr.strip()}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Run privileged disposable namespace checks")
    args = parser.parse_args(argv)
    if not args.execute:
        print("DRY RUN: would verify numeric IPv4/IPv6 UDP endpoint exceptions and unrelated underlay drops")
        print("in disposable namespaces; no real WireGuard tunnel or host networking is modified.")
        return 0
    missing = [tool for tool in ("ip", "nft") if shutil.which(tool) is None]
    if missing:
        parser.error("Missing prerequisites: " + ", ".join(missing))
    if os.geteuid() != 0:
        parser.error("--execute requires root")
    try:
        probe("vpnprobe-" + secrets.token_hex(4))
    except (EndpointProbeError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
