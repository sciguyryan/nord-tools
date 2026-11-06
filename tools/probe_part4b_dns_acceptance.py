#!/usr/bin/env python3
"""Privileged disposable DNS route, resolver and tunnel-loss acceptance.

The probe uses a real WireGuard pair and a default-drop nftables policy in
isolated namespaces. It does not modify the host resolver or firewall.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nord_tools_internal.nordvpn_dns_confinement import (
    verify_dns_routes,
    verify_dns_peer_allowed_ips,
    verify_resolver_file,
)
from nord_tools_internal.nordvpn_resolver_install import install_namespace_resolver, remove_namespace_resolver
from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy
from tools.probe_two_wireguard import HarnessError, pair, run
from tools.probe_wireguard_host_integrity import observe, verify


DNS_POLICY = NamespaceResolverPolicy(("1.1.1.1", "2606:4700:4700::1111"))


class DNSAcceptanceError(RuntimeError):
    """The DNS confinement acceptance contract was not met."""


def _route_lookup(namespace: str, address: str, family: str) -> str:
    result = run("ip", "netns", "exec", namespace, "ip", family, "route", "get", address, check=False)
    if result.returncode:
        return "unreachable"
    return result.stdout


def _require_no_underlay_fallback(namespace: str, underlay: str) -> None:
    for address, family in (("1.1.1.1", "-4"), ("2606:4700:4700::1111", "-6")):
        output = _route_lookup(namespace, address, family)
        if f"dev {underlay}" in output or ("dev wgtest" not in output and output != "unreachable"):
            raise DNSAcceptanceError(f"DNS route escaped WireGuard after shutdown: {family}")
        print(f"PASS: {family} DNS has no underlay fallback after WireGuard shutdown")


def _install_isolation(namespace: str, underlay: str, endpoint: str, port: int) -> None:
    """Install an explicit default-drop policy with one pinned endpoint exception."""
    rules = f'''table inet nt_dns_accept {{
        chain output {{
            type filter hook output priority 0; policy drop;
            oifname "lo" accept
            oifname "wgtest" accept
            oifname "{underlay}" ip daddr {endpoint} udp dport {port} accept
        }}
        chain input {{
            type filter hook input priority 0; policy drop;
            iifname "lo" accept
            ct state established,related accept
            iifname "{underlay}" ip saddr {endpoint} udp sport {port} accept
            iifname "wgtest" accept
        }}
    }}'''
    run("ip", "netns", "exec", namespace, "nft", "-f", "-", input_text=rules)


def _exchange_dns_packets(client: str, server: str) -> None:
    """Exchange DNS-shaped UDP datagrams over both real WireGuard families."""
    server_code = """import select, socket, sys
sockets = []
for family, address in ((socket.AF_INET, '1.1.1.1'), (socket.AF_INET6, '2606:4700:4700::1111')):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((address, 53535))
    sockets.append(sock)
print('READY', flush=True)
for _ in range(2):
    ready, _, _ = select.select(sockets, [], [], 10)
    if not ready:
        sys.exit(2)
    payload, peer = ready[0].recvfrom(512)
    if payload != b'nt-dns-probe':
        sys.exit(3)
    ready[0].sendto(b'nt-dns-reply', peer)
"""
    client_code = """import socket
for family, address in ((socket.AF_INET, '1.1.1.1'), (socket.AF_INET6, '2606:4700:4700::1111')):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(6)
    sock.sendto(b'nt-dns-probe', (address, 53535))
    assert sock.recvfrom(512)[0] == b'nt-dns-reply'
"""
    process = subprocess.Popen(
        ["ip", "netns", "exec", server, sys.executable, "-c", server_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        if process.stdout is None or process.stdout.readline().strip() != "READY":
            raise DNSAcceptanceError("DNS packet responder could not start")
        result = subprocess.run(
            ["ip", "netns", "exec", client, sys.executable, "-c", client_code],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if result.returncode:
            raise DNSAcceptanceError(f"real WireGuard DNS UDP exchange failed: {result.stderr.strip()}")
        if process.wait(timeout=10):
            raise DNSAcceptanceError("DNS packet responder did not receive both datagrams")
        print("PASS: IPv4 and IPv6 DNS-shaped UDP datagrams traversed real WireGuard")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()


def experiment(token: str) -> None:
    """Exercise DNS route confinement and resolver readback in a real tunnel."""
    client, server = f"nd{token}c", f"nd{token}s"
    client_link, server_link = f"d{token}c", f"d{token}s"
    created: list[str] = []
    resolver = None
    try:
        for name in (client, server):
            run("ip", "netns", "add", name)
            created.append(name)
        run("ip", "link", "add", client_link, "type", "veth", "peer", "name", server_link)
        # Pair establishes a fresh, authenticated real WireGuard exchange.
        pair(client, server, client_link, server_link, 1)
        # Permit both address families at the cryptographic peer boundary.
        peer = run("ip", "netns", "exec", client, "wg", "show", "wgtest", "peers").stdout.strip()
        if len(peer.splitlines()) != 1 or not peer:
            raise DNSAcceptanceError("cannot identify the single WireGuard peer")
        run("ip", "netns", "exec", client, "wg", "set", "wgtest", "peer", peer, "allowed-ips", "0.0.0.0/0,::/0")
        # Bind both DNS destinations to the peer's tunnel interface, and
        # establish a return route for the client's IPv6 tunnel address.
        run("ip", "-n", server, "addr", "add", "1.1.1.1/32", "dev", "wgtest")
        run("ip", "-n", server, "-6", "addr", "add", "2606:4700:4700::1111/128", "dev", "wgtest")
        run("ip", "-n", client, "-6", "addr", "add", "fd42:213::2/128", "dev", "wgtest")
        client_peer = run("ip", "netns", "exec", server, "wg", "show", "wgtest", "peers").stdout.strip()
        run(
            "ip",
            "netns",
            "exec",
            server,
            "wg",
            "set",
            "wgtest",
            "peer",
            client_peer,
            "allowed-ips",
            "10.213.1.2/32,fd42:213::2/128",
        )
        run("ip", "-n", server, "-6", "route", "add", "fd42:213::2/128", "dev", "wgtest")
        _install_isolation(client, client_link, "198.18.1.1", 51001)
        run("ip", "-n", client, "-4", "route", "add", "default", "dev", "wgtest")
        run("ip", "-n", client, "-6", "route", "add", "default", "dev", "wgtest")
        verify_dns_routes(client, "wgtest", DNS_POLICY)
        verify_dns_peer_allowed_ips(client, "wgtest", DNS_POLICY)
        print("PASS: IPv4 and IPv6 DNS destinations route exclusively through real WireGuard")
        resolver = install_namespace_resolver(client, DNS_POLICY)
        verify_resolver_file(client, DNS_POLICY)
        print("PASS: namespace resolver installed and verified without changing the host resolver")
        # Confirm the resolver is actually visible to processes in the namespace.
        mounted = run("ip", "netns", "exec", client, "cat", "/etc/resolv.conf").stdout
        if mounted != DNS_POLICY.render_resolv_conf():
            raise DNSAcceptanceError("namespace process does not see the pinned resolver")
        print("PASS: namespace process observes the pinned resolver configuration")
        _exchange_dns_packets(client, server)
        # The underlay must not become an alternative route after the tunnel fails.
        run("ip", "-n", client, "link", "set", "wgtest", "down")
        _require_no_underlay_fallback(client, client_link)
    finally:
        failures = []
        if resolver is not None:
            try:
                remove_namespace_resolver(resolver)
            except OSError as exc:
                failures.append(f"resolver: {exc}")
        for name in reversed(created):
            result = run("ip", "netns", "del", name, check=False)
            if result.returncode:
                failures.append(name)
        for link in (client_link, server_link):
            if run("ip", "link", "show", "dev", link, check=False).returncode == 0:
                if run("ip", "link", "del", "dev", link, check=False).returncode:
                    failures.append(link)
        if failures:
            raise DNSAcceptanceError("Manual inspection required after failed cleanup: " + ", ".join(failures))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-privileged", action="store_true", help="authorise the disposable real WireGuard experiment"
    )
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: real WireGuard DNS route, namespace resolver and tunnel-loss acceptance")
        print("No host firewall, host resolver or host routes will be changed.")
        return 0
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("--run-privileged requires Linux root")
    missing = [name for name in ("ip", "wg", "nft", "ping") if shutil.which(name) is None]
    if missing:
        parser.error("Missing prerequisites: " + ", ".join(missing))
    if not Path("/etc/netns").is_dir():
        parser.error("/etc/netns must exist as a trusted directory before running this probe")
    try:
        before = observe()
        experiment(secrets.token_hex(3))
        verify(before, observe())
    except (DNSAcceptanceError, HarnessError, OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print("PASS: disposable real WireGuard DNS route and resolver acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
