"""Application-level DNS and bypass checks for a production-owned WireGuard namespace.

All traffic originates in the namespace installed by the production executor.
The peer is a disposable local test endpoint, not a public DNS service.
"""

from __future__ import annotations

import subprocess
import sys


class ApplicationConfinementError(RuntimeError):
    """A production-owned application traffic invariant was not demonstrated."""


# This program runs in a fresh Python process inside the production namespace.
# A real DNS question and response are required, not merely a UDP datagram.
DNS_CLIENT = r"""
import socket
import struct
import sys

address, family = sys.argv[1:]
family = socket.AF_INET6 if family == '6' else socket.AF_INET
transaction = b'\x4e\x54'
name = b'\x08nordtest\x07invalid\x00'
question = transaction + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + name + b'\x00\x01\x00\x01'
with socket.socket(family, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)
    sock.sendto(question, (address, 53))
    response, source = sock.recvfrom(4096)
if source[0] != address or len(response) < 12:
    sys.exit(2)
if response[:2] != transaction or response[2:4] != b'\x81\x83':
    sys.exit(3)
if response[4:6] != b'\x00\x01' or response[6:12] != b'\x00' * 6:
    sys.exit(4)
if response[12:] != question[12:]:
    sys.exit(5)
"""


# A blocked send may succeed at the socket API while the firewall discards
# the packet. Therefore the receiver's timeout, not the sender's return code,
# determines whether an underlay bypass has occurred.
UNDERLAY_LISTENER = r"""
import socket
import sys

family = socket.AF_INET6 if sys.argv[1] == '6' else socket.AF_INET
kind = socket.SOCK_STREAM if sys.argv[2] == 'tcp' else socket.SOCK_DGRAM
with socket.socket(family, kind) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((sys.argv[3], int(sys.argv[4])))
    if kind == socket.SOCK_STREAM:
        sock.listen(1)
    sock.settimeout(3)
    print('READY', flush=True)
    try:
        if kind == socket.SOCK_STREAM:
            connection, _ = sock.accept()
            connection.close()
        else:
            sock.recvfrom(128)
    except socket.timeout:
        sys.exit(0)
    sys.exit(3)
"""

UNDERLAY_CLIENT = r"""
import socket
import sys

family = socket.AF_INET6 if sys.argv[1] == '6' else socket.AF_INET
kind = socket.SOCK_STREAM if sys.argv[2] == 'tcp' else socket.SOCK_DGRAM
with socket.socket(family, kind) as sock:
    sock.settimeout(2)
    try:
        if kind == socket.SOCK_STREAM:
            sock.connect((sys.argv[3], int(sys.argv[4])))
        else:
            sock.sendto(b'forbidden', (sys.argv[3], int(sys.argv[4])))
    except OSError as exc:
        # A failed connect is not evidence of a leak. The independent
        # listener must still prove that no traffic was delivered.
        print(f'BLOCKED_SOCKET_ERROR:{exc.errno}:{exc.strerror}', file=sys.stderr)
        sys.exit(0)
"""


def _execute(namespace: str, script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["ip", "netns", "exec", namespace, sys.executable, "-I", "-c", script, *arguments],
        capture_output=True,
        text=True,
        timeout=12,
        check=False,
    )


def verify_application_dns(namespace: str, resolver: str, *, family: int = 4) -> None:
    """Require a valid deterministic DNS response from the VPN-side resolver."""
    result = _execute(namespace, DNS_CLIENT, resolver, str(family))
    if result.returncode:
        raise ApplicationConfinementError(
            f"IPv{family} application DNS response failed (exit {result.returncode}): " + result.stderr.strip()[:160]
        )


def verify_underlay_bypass(
    namespace: str,
    server_namespace: str,
    address: str,
    port: int,
    *,
    family: int = 4,
    protocol: str = "udp",
) -> None:
    """Reject a delivered TCP connection or UDP datagram on the underlay."""
    if protocol not in {"tcp", "udp"} or family not in {4, 6}:
        raise ValueError("unsupported protocol or address family")
    listener = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            server_namespace,
            sys.executable,
            "-I",
            "-c",
            UNDERLAY_LISTENER,
            str(family),
            protocol,
            address,
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        if listener.stdout is None or listener.stdout.readline().strip() != "READY":
            raise ApplicationConfinementError("underlay test listener did not become ready")
        sender = _execute(namespace, UNDERLAY_CLIENT, str(family), protocol, address, str(port))
        if sender.returncode:
            raise ApplicationConfinementError(
                f"underlay {protocol} sender failed unexpectedly (exit {sender.returncode}): "
                f"{sender.stderr.strip()[-1200:]}"
            )
        if listener.wait(timeout=6) != 0:
            raise ApplicationConfinementError(f"IPv{family} application {protocol} escaped onto underlay")
    finally:
        if listener.poll() is None:
            listener.kill()
            listener.wait(timeout=5)
        if listener.stdout is not None:
            listener.stdout.close()
        if listener.stderr is not None:
            listener.stderr.close()


def verify_dns_unavailable(namespace: str, resolver: str, *, family: int) -> None:
    """Require the application to lose DNS service when its tunnel is down."""
    if family not in {4, 6}:
        raise ValueError("unsupported address family")
    result = _execute(namespace, DNS_CLIENT, resolver, str(family))
    if result.returncode == 0:
        raise ApplicationConfinementError(f"IPv{family} application DNS unexpectedly succeeded with the tunnel down")
