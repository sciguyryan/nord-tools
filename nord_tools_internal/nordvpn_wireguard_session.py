"""Experimental WireGuard configuration within a caller-owned disposable namespace.

This is deliberately not a persistent provisioner. The caller must retain its
creation-time namespace descriptor and arrange its own durable intent handling.
No routes, DNS settings or host networking resources are modified here.
"""

from __future__ import annotations

import os
import subprocess

from nord_tools_internal.nordvpn_namespace_ownership import OwnedNamespace
from nord_tools_internal.nordvpn_wireguard_credentials import private_key_from_fd
from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification


class SessionError(RuntimeError):
    """Disposable WireGuard configuration was refused or failed."""


def _run(argv: list[str], *, pass_fds: tuple[int, ...] = ()) -> None:
    try:
        result = subprocess.run(argv, check=False, capture_output=True, timeout=15, pass_fds=pass_fds)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SessionError("disposable WireGuard command could not complete") from exc
    if result.returncode:
        # Command output may include sensitive configuration or host details.
        raise SessionError("disposable WireGuard command failed")


def configure_disposable_wireguard(spec: TunnelSpecification, owned: OwnedNamespace, key_fd: int) -> None:
    """Configure one new interface, without routes or cleanup authority.

    Requires root and an already-created, descriptor-bound disposable namespace.
    Any failure leaves cleanup and uncertainty handling to the caller. In
    particular, this function must not be used for persistent VPN management.
    """
    if not isinstance(spec, TunnelSpecification) or not isinstance(owned, OwnedNamespace):
        raise SessionError("validated tunnel specification and namespace ownership are required")
    if spec.namespace != owned.name:
        raise SessionError("namespace identity does not match the tunnel specification")
    owned.verify()
    with private_key_from_fd(key_fd) as private_key:
        # Validate the credential before making any kernel changes. The pipe
        # below transfers the key to wg without command-line arguments or a
        # persistent configuration file.
        owned.verify()
        _run(["ip", "-n", spec.namespace, "link", "add", "dev", spec.interface, "type", "wireguard"])
        owned.verify()
        read_fd, write_fd = os.pipe()
        try:
            try:
                view = memoryview(private_key)
                while view:
                    count = os.write(write_fd, view)
                    view = view[count:]
            finally:
                os.close(write_fd)
            endpoint = (
                f"[{spec.endpoint_address}]:{spec.endpoint_port}"
                if ":" in spec.endpoint_address
                else f"{spec.endpoint_address}:{spec.endpoint_port}"
            )
            _run(
                [
                    "ip",
                    "netns",
                    "exec",
                    spec.namespace,
                    "wg",
                    "set",
                    spec.interface,
                    "private-key",
                    f"/proc/self/fd/{read_fd}",
                    "peer",
                    spec.peer_public_key,
                    "endpoint",
                    endpoint,
                    "allowed-ips",
                    ",".join(spec.peer_allowed_ips),
                ],
                pass_fds=(read_fd,),
            )
        finally:
            os.close(read_fd)
        owned.verify()
        _run(["ip", "-n", spec.namespace, "address", "add", spec.tunnel_address, "dev", spec.interface])
        owned.verify()
        _run(["ip", "-n", spec.namespace, "link", "set", "dev", spec.interface, "up"])
        owned.verify()
