"""Read-only safety assessment for a prospective host-domain default tunnel.

This module deliberately grants no kernel mutation authority. Host routing needs
an independently verified rollback and firewall installation protocol before an
executor may use a plan; a syntactically valid plan is not that evidence.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping

from nord_tools_internal.nordvpn_registry import RegistryError


_REQUIRED_DEFAULTS = ("0.0.0.0/0", "::/0")


def assess_host_default_protection(plan: object) -> dict:
    """Describe the minimum host protection requirements without changing state.

    Reject incomplete or ambiguous endpoint, DNS and dual-stack declarations.
    A caller cannot turn this assessment into permission to alter host routes.
    """
    if not isinstance(plan, Mapping):
        raise RegistryError("host default protection requires a tunnel plan mapping")
    required = {"endpoint_address", "endpoint_port", "tunnel_address", "peer_allowed_ips", "dns_servers"}
    if not required <= plan.keys():
        raise RegistryError("host default protection requires endpoint, tunnel, allowed IPs and DNS servers")
    try:
        endpoint = ipaddress.ip_address(plan["endpoint_address"])
        tunnel = ipaddress.ip_interface(plan["tunnel_address"])
    except (ValueError, TypeError) as exc:
        raise RegistryError("host default protection requires numeric endpoint and tunnel addresses") from exc
    if endpoint.is_unspecified or endpoint.is_multicast or endpoint.is_loopback or endpoint.is_link_local:
        raise RegistryError("host default endpoint is unsuitable for a pinned underlay exception")
    if tunnel.ip.is_unspecified or tunnel.ip.is_multicast:
        raise RegistryError("host default tunnel address is invalid")
    port = plan["endpoint_port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise RegistryError("host default endpoint port is invalid")
    allowed = plan["peer_allowed_ips"]
    if not isinstance(allowed, (tuple, list)) or not allowed or any(not isinstance(x, str) for x in allowed):
        raise RegistryError("host default allowed IPs must be canonical network strings")
    try:
        networks = [ipaddress.ip_network(x, strict=True) for x in allowed]
    except ValueError as exc:
        raise RegistryError("host default allowed IPs contain an invalid network") from exc
    if len(set(allowed)) != len(allowed) or any(str(network) != text for network, text in zip(networks, allowed)):
        raise RegistryError("host default allowed IPs must be unique and canonical")
    if set(allowed) != set(_REQUIRED_DEFAULTS):
        raise RegistryError("host default protection requires exactly both IPv4 and IPv6 default routes")
    dns = plan["dns_servers"]
    if not isinstance(dns, (tuple, list)) or not dns or any(not isinstance(x, str) for x in dns):
        raise RegistryError("host default protection requires pinned numeric DNS servers")
    try:
        servers = [ipaddress.ip_address(x) for x in dns]
    except ValueError as exc:
        raise RegistryError("host default DNS servers must be numeric IP literals") from exc
    if len(set(dns)) != len(dns) or any(
        str(server) != text
        or server.is_unspecified
        or server.is_multicast
        or server.is_loopback
        or server.is_link_local
        for server, text in zip(servers, dns)
    ):
        raise RegistryError("host default DNS servers must be distinct canonical unicast addresses")
    return {
        "version": 1,
        "mode": "host_default_protection_assessment",
        "network_changes_applied": False,
        "mutation_authorised": False,
        "endpoint_exception": {"address": str(endpoint), "port": port, "transport": "udp"},
        "required_tunnel_routes": list(_REQUIRED_DEFAULTS),
        "dns_servers": [str(server) for server in servers],
        "required_guards": [
            "host_output_deny_before_route_change",
            "endpoint_only_underlay_exception_bound_to_verified_egress",
            "ipv4_ipv6_forward_and_output_confinement",
            "resolver_atomic_switch_and_recovery",
            "crash_durable_host_state_and_independent_rollback",
            "live_packet_and_dns_leak_acceptance",
        ],
        "executable": False,
        "reason": "host-domain kernel mutation and rollback authority have not been established",
    }
