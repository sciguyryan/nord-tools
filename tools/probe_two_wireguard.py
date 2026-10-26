#!/usr/bin/env python3
"""Disposable two-pair WireGuard integration experiment, never a host VPN installer.

Only explicitly created network namespaces and veth devices are modified. The
host's default route, DNS, nftables tables and existing VPNs are untouched.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from nord_tools_internal.nordvpn_wireguard_observation import ObservationError, require_fresh_exchange


class HarnessError(RuntimeError):
    """The disposable experiment could not safely complete."""


def run(*args: str, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), input=input_text, text=True, capture_output=True, check=check)


def identifiers(token: str) -> list[tuple[str, str, str, str]]:
    """Return namespace and interface names within Linux's 15-byte limit."""
    if len(token) != 6 or any(ch not in "0123456789abcdef" for ch in token):
        raise ValueError("Expected a six-character hexadecimal token")
    return [(f"nt{token}c{i}", f"nt{token}s{i}", f"v{token}{i}c", f"v{token}{i}s") for i in (1, 2)]


def keypair() -> tuple[str, str]:
    private = run("wg", "genkey").stdout.strip()
    public = run("wg", "pubkey", input_text=private + "\n").stdout.strip()
    if not private or not public:
        raise HarnessError("WireGuard did not produce a keypair")
    return private, public


def configure_key(
    namespace: str, interface: str, private: str, peer: str, endpoint: str, allowed: str, port: int
) -> None:
    # wg requires a key file. A private, mode-0600 temporary file is removed
    # immediately after use; never place secret keys in command arguments.
    with tempfile.TemporaryDirectory(prefix="nt-wg-", dir=None) as directory:
        key_file = Path(directory) / "key"
        key_file.write_text(private + "\n", encoding="ascii")
        key_file.chmod(0o600)
        run(
            "ip",
            "netns",
            "exec",
            namespace,
            "wg",
            "set",
            interface,
            "listen-port",
            str(port),
            "private-key",
            str(key_file),
            "peer",
            peer,
            "allowed-ips",
            allowed,
            "endpoint",
            endpoint,
            "persistent-keepalive",
            "1",
        )


def pair(client: str, server: str, client_link: str, server_link: str, index: int) -> None:
    """Create one isolated WireGuard pair with an explicit underlay endpoint."""
    underlay = f"198.18.{index}"
    tunnel = f"10.213.{index}"
    port = 51000 + index
    run("ip", "link", "set", client_link, "netns", client)
    run("ip", "link", "set", server_link, "netns", server)
    for namespace, link, address in ((client, client_link, "2"), (server, server_link, "1")):
        run("ip", "-n", namespace, "link", "set", "lo", "up")
        run("ip", "-n", namespace, "addr", "add", f"{underlay}.{address}/30", "dev", link)
        run("ip", "-n", namespace, "link", "set", link, "up")
        run("ip", "-n", namespace, "link", "add", "wgtest", "type", "wireguard")
    client_private, client_public = keypair()
    server_private, server_public = keypair()
    configure_key(client, "wgtest", client_private, server_public, f"{underlay}.1:{port}", f"{tunnel}.1/32", port + 100)
    configure_key(server, "wgtest", server_private, client_public, f"{underlay}.2:{port + 100}", f"{tunnel}.2/32", port)
    for namespace, address in ((client, "2"), (server, "1")):
        run("ip", "-n", namespace, "addr", "add", f"{tunnel}.{address}/30", "dev", "wgtest")
        run("ip", "-n", namespace, "link", "set", "wgtest", "up")
    run("ip", "-n", client, "route", "add", f"{tunnel}.1/32", "dev", "wgtest")
    run("ip", "-n", server, "route", "add", f"{tunnel}.2/32", "dev", "wgtest")
    # No default route is installed in any namespace or on the host.
    started_at = int(time.time()) - 1
    run("ip", "netns", "exec", client, "ping", "-n", "-c", "2", "-W", "2", f"{tunnel}.1")
    dump = run("ip", "netns", "exec", client, "wg", "show", "wgtest", "dump").stdout
    try:
        require_fresh_exchange(dump, server_public, started_at)
    except ObservationError as exc:
        raise HarnessError(f"Pair {index} did not establish a fresh WireGuard exchange: {exc}") from exc
    print(f"PASS: independent WireGuard pair {index} exchanged tunnel packets")


def verify_shutdown(client: str, index: int) -> None:
    """Verify a stopped tunnel cannot reach its peer tunnel address."""
    run("ip", "-n", client, "link", "set", "wgtest", "down")
    target = f"10.213.{index}.1"
    failed = run("ip", "netns", "exec", client, "ping", "-n", "-c", "1", "-W", "1", target, check=False)
    if failed.returncode == 0:
        raise HarnessError(f"Pair {index} remained reachable after tunnel shutdown")
    print(f"PASS: pair {index} unavailable after WireGuard shutdown")


def experiment(token: str) -> None:
    created: list[str] = []
    # A failed veth move can leave a host-side interface. Keep exact names for
    # conservative, ownership-scoped best-effort cleanup of this invocation.
    links: list[str] = []
    try:
        for client, server, client_link, server_link in identifiers(token):
            for namespace in (client, server):
                result = run("ip", "netns", "add", namespace, check=False)
                if result.returncode:
                    raise HarnessError(result.stderr.strip() or f"Cannot create {namespace}")
                created.append(namespace)
            # Claim both interface names only after a successful atomic veth creation.
            run("ip", "link", "add", client_link, "type", "veth", "peer", "name", server_link)
            links.extend((client_link, server_link))
            pair(client, server, client_link, server_link, int(client[-1]))
        # Both pairs are still up here; verify one survives failure of the other.
        first, second = identifiers(token)
        verify_shutdown(first[0], 1)
        run("ip", "netns", "exec", second[0], "ping", "-n", "-c", "1", "-W", "2", "10.213.2.1")
        print("PASS: second pair remains reachable after first pair shuts down")
        verify_shutdown(second[0], 2)
        print("PASS: two independent disposable WireGuard pairs completed")
    finally:
        failures = []
        for namespace in reversed(created):
            result = run("ip", "netns", "del", namespace, check=False)
            if result.returncode:
                failures.append(namespace)
        for link in links:
            # Only delete an exact random name if it remains in the host namespace.
            if run("ip", "link", "show", "dev", link, check=False).returncode == 0:
                result = run("ip", "link", "del", "dev", link, check=False)
                if result.returncode:
                    failures.append(link)
        if failures:
            raise HarnessError("Manual inspection required; cleanup failed for: " + ", ".join(failures))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Run the privileged disposable experiment")
    args = parser.parse_args(argv)
    if not args.execute:
        print("DRY RUN: create four disposable namespaces and two independent WireGuard pairs.")
        print("No host routes, firewall or DNS settings will be changed. Requires Linux root, ip, wg and ping.")
        print("This is not a production kill-switch, provider or DNS leak test.")
        return 0
    if sys.platform != "linux":
        parser.error("Only Linux is supported")
    missing = [name for name in ("ip", "wg", "ping") if shutil.which(name) is None]
    if missing:
        parser.error("Missing prerequisites: " + ", ".join(missing))
    if os.geteuid() != 0:
        parser.error("--execute requires root")
    try:
        experiment(secrets.token_hex(3))
    except (HarnessError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
