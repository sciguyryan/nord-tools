"""Offline firewall policy for a disposable, isolated network namespace.

This module renders a proposed nftables ruleset. It does not execute it,
configure DNS, or establish that the host or namespace is leak-proof.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re


class IsolationPolicyError(ValueError):
    """An isolation policy cannot be represented safely."""


_INTERFACE = re.compile(r"[a-zA-Z0-9_.-]{1,15}\Z")


@dataclass(frozen=True)
class NamespaceIsolationPolicy:
    """Restrict output to the tunnel and a single numeric WireGuard endpoint."""

    tunnel_interface: str
    underlay_interface: str
    endpoint_address: str
    endpoint_port: int

    def __post_init__(self) -> None:
        for name in (self.tunnel_interface, self.underlay_interface):
            if not isinstance(name, str) or not _INTERFACE.fullmatch(name):
                raise IsolationPolicyError("invalid interface name")
        if self.tunnel_interface == self.underlay_interface:
            raise IsolationPolicyError("tunnel and underlay interfaces must differ")
        try:
            endpoint = ipaddress.ip_address(self.endpoint_address)
        except (TypeError, ValueError) as exc:
            raise IsolationPolicyError("endpoint must be a numeric IP address") from exc
        if endpoint.is_unspecified or endpoint.is_multicast or endpoint.is_loopback or endpoint.is_link_local:
            raise IsolationPolicyError("endpoint address is not a routable unicast address")
        if type(self.endpoint_port) is not int or not 1 <= self.endpoint_port <= 65535:
            raise IsolationPolicyError("invalid WireGuard endpoint port")

    def render_nft(self) -> str:
        """Render a namespace-local *candidate*, never a host firewall script.

        A dedicated inet table has default-drop input, output and forward
        policies. Only loopback, established replies, tunnel output and one
        numeric UDP underlay endpoint are allowed. This is not an atomic
        installation protocol and does not configure resolver confinement.
        """
        endpoint = ipaddress.ip_address(self.endpoint_address)
        family = "ip6" if endpoint.version == 6 else "ip"
        return "\n".join(
            (
                "table inet nord_tools_isolation {",
                "  chain input {",
                "    type filter hook input priority 0; policy drop;",
                '    iifname "lo" accept',
                "    ct state established,related accept",
                "  }",
                "  chain forward {",
                "    type filter hook forward priority 0; policy drop;",
                "  }",
                "  chain output {",
                "    type filter hook output priority 0; policy drop;",
                '    oifname "lo" accept',
                f'    oifname "{self.tunnel_interface}" accept',
                f'    oifname "{self.underlay_interface}" {family} daddr {endpoint} udp dport {self.endpoint_port} accept',
                "  }",
                "}",
                "",
            )
        )

    def public_plan(self) -> dict[str, object]:
        """Expose the proposed isolation boundary without claiming enforcement."""
        return {
            "version": 1,
            "mode": "offline_namespace_isolation",
            "network_changes_applied": False,
            "firewall_installed": False,
            "dns_confined": False,
            "host_firewall_modified": False,
            "requires_atomic_pretraffic_installation": True,
            "ruleset": self.render_nft(),
        }
