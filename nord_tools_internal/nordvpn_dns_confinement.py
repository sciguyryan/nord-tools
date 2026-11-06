"""Conservative DNS route and resolver readback for an isolated VPN namespace.

DNS configuration is not a security boundary on its own. The caller must
install a fail-closed firewall before allowing namespace traffic and must
verify both families' default routes through WireGuard separately.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import subprocess

from .nordvpn_resolver_policy import NamespaceResolverPolicy


class DNSConfinementError(RuntimeError):
    """A namespace DNS destination cannot be certified as tunnel-routed."""


def verify_dns_peer_allowed_ips(namespace: str, tunnel_interface: str, policy: NamespaceResolverPolicy) -> None:
    """Require the live WireGuard peer to permit every pinned DNS destination.

    A route via WireGuard is insufficient when the peer's AllowedIPs excludes
    the destination: WireGuard will reject the packet before encryption.
    """
    try:
        result = subprocess.run(
            ["ip", "netns", "exec", namespace, "wg", "show", tunnel_interface, "allowed-ips"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = [line.split() for line in result.stdout.splitlines()]
        if len(lines) != 1 or len(lines[0]) < 2:
            raise DNSConfinementError("WireGuard DNS peer allowed IPs are ambiguous")
        networks = [ipaddress.ip_network(part.strip(","), strict=False) for part in lines[0][1:]]
        if not all(any(ipaddress.ip_address(server) in network for network in networks) for server in policy.servers):
            raise DNSConfinementError("a DNS destination is outside the live WireGuard peer AllowedIPs")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise DNSConfinementError("WireGuard DNS peer AllowedIPs readback failed") from exc


def verify_dns_routes(namespace: str, tunnel_interface: str, policy: NamespaceResolverPolicy) -> None:
    """Require each configured server's actual route to use WireGuard.

    Route lookup is destination-specific; checking only the default route
    would miss a more-specific underlay route. Never resolve a hostname here.
    """
    if not isinstance(policy, NamespaceResolverPolicy):
        raise DNSConfinementError("validated DNS policy required")
    for server in policy.servers:
        family = "-6" if ipaddress.ip_address(server).version == 6 else "-4"
        try:
            result = subprocess.run(
                ["ip", "netns", "exec", namespace, "ip", "-j", family, "route", "get", server],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            routes = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise DNSConfinementError("DNS route readback failed") from exc
        if (
            not isinstance(routes, list)
            or len(routes) != 1
            or not isinstance(routes[0], dict)
            or routes[0].get("dev") != tunnel_interface
            or routes[0].get("type", "unicast") != "unicast"
        ):
            raise DNSConfinementError("DNS destination is not exclusively routed through WireGuard")


def verify_resolver_file(namespace: str, policy: NamespaceResolverPolicy, *, root: Path = Path("/etc/netns")) -> None:
    """Refuse resolver replacement, extra directives or a missing namespace file."""
    import os
    import stat

    directory = root / namespace
    try:
        parent = root.lstat()
        entry = directory.lstat()
        path = directory / "resolv.conf"
        file_info = path.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_mode & 0o022
            or not stat.S_ISDIR(entry.st_mode)
            or entry.st_mode & 0o022
            or not stat.S_ISREG(file_info.st_mode)
            or file_info.st_mode & 0o022
            or file_info.st_nlink != 1
            or len(list(directory.iterdir())) != 1
        ):
            raise DNSConfinementError("unsafe namespace resolver filesystem state")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "r", encoding="ascii") as stream:
            held = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(held.st_mode)
                or held.st_dev != file_info.st_dev
                or held.st_ino != file_info.st_ino
                or held.st_nlink != 1
                or held.st_mode & 0o022
            ):
                raise DNSConfinementError("namespace resolver changed during readback")
            content = stream.read(4096)
            if stream.read(1):
                raise DNSConfinementError("oversized namespace resolver")
    except (OSError, UnicodeError) as exc:
        raise DNSConfinementError("namespace resolver readback failed") from exc
    if content != policy.render_resolv_conf():
        raise DNSConfinementError("namespace resolver differs from pinned policy")
