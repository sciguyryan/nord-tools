"""Offline resolver configuration for an isolated Linux network namespace.

This module does not write resolv.conf, change the host resolver, or prove
that a resolver is reachable only through a WireGuard tunnel. Installation
and routing verification are separate privileged security boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress


class ResolverPolicyError(ValueError):
    """The proposed namespace resolver configuration is unsafe or invalid."""


@dataclass(frozen=True)
class NamespaceResolverPolicy:
    """Specify numeric DNS servers for a future namespace-local resolv.conf.

    Numeric addresses avoid invoking the host resolver during configuration.
    They must subsequently be routed through the protected tunnel, not the
    underlay. This object cannot establish that routing property by itself.
    """

    servers: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.servers, tuple) or not 1 <= len(self.servers) <= 3:
            raise ResolverPolicyError("one to three numeric DNS servers are required")
        normalised: list[str] = []
        for server in self.servers:
            if not isinstance(server, str):
                raise ResolverPolicyError("DNS servers must be numeric IP addresses")
            try:
                address = ipaddress.ip_address(server)
            except ValueError as exc:
                raise ResolverPolicyError("DNS servers must be numeric IP addresses") from exc
            if (
                address.is_unspecified
                or address.is_multicast
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
            ):
                raise ResolverPolicyError("DNS server address is not suitable for tunnel routing")
            canonical = str(address)
            if canonical in normalised:
                raise ResolverPolicyError("duplicate DNS server")
            normalised.append(canonical)
        object.__setattr__(self, "servers", tuple(normalised))

    def render_resolv_conf(self) -> str:
        """Render deterministic contents, without writing a filesystem path."""
        return "".join(f"nameserver {server}\n" for server in self.servers) + "options attempts:1 timeout:2\n"

    def public_plan(self) -> dict[str, object]:
        """Report proposal status without claiming enforcement or DNS isolation."""
        return {
            "version": 1,
            "mode": "offline_namespace_resolver",
            "resolver_configuration_applied": False,
            "dns_confined": False,
            "requires_tunnel_route_verification": True,
            "requires_namespace_local_installation": True,
            "resolv_conf": self.render_resolv_conf(),
        }
