"""Host-default assessment and the separate executable plan contract.

This module deliberately grants no kernel mutation authority. Host routing needs
an independently verified rollback and firewall installation protocol before an
executor may use a plan; a syntactically valid plan is not that evidence.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping

from nord_tools_internal.nordvpn_registry import RegistryError


_REQUIRED_DEFAULTS = ("0.0.0.0/0", "::/0")
_INTERFACE = re.compile(r"[a-zA-Z0-9_.-]{1,15}\Z")
_GENERATION = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")
_PUBLIC_KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")


@dataclass(frozen=True)
class HostProtectionPlan:
    """Versioned, credential-free plan for the supported host arrangement.

    This type validates enough information for the host executor to perform a
    fresh inventory and authority preflight.  It is not mutation authority by
    itself; the executor additionally requires the lifecycle lock, a durable
    transaction store, root execution and matching live observations.
    """

    generation: str
    interface: str
    peer_public_key: str
    endpoint_address: str
    endpoint_port: int
    tunnel_addresses: tuple[str, str]
    dns_servers: tuple[str, ...]
    egress_interface: str
    egress_ifindex: int
    egress_source_address: str
    route_table: int
    endpoint_rule_priority: int
    tunnel_rule_priority: int
    fwmark: int
    resolver_mode: str = "systemd-resolved"
    firewall_family: str = "inet"
    firewall_table: str = "nord_tools_host"
    firewall_priority: int = -200
    peer_allowed_ips: tuple[str, str] = _REQUIRED_DEFAULTS
    version: int = 1

    def __post_init__(self) -> None:
        if self.version != 1:
            raise RegistryError("host protection plan requires version 1")
        if not isinstance(self.generation, str) or not _GENERATION.fullmatch(self.generation):
            raise RegistryError("invalid host protection generation")
        for value, label in ((self.interface, "tunnel"), (self.egress_interface, "egress")):
            if not isinstance(value, str) or not _INTERFACE.fullmatch(value):
                raise RegistryError(f"invalid host {label} interface")
        if self.interface == self.egress_interface:
            raise RegistryError("host tunnel and egress interfaces must differ")
        if not isinstance(self.peer_public_key, str) or not _PUBLIC_KEY.fullmatch(self.peer_public_key):
            raise RegistryError("invalid WireGuard peer public key")
        try:
            decoded = base64.b64decode(self.peer_public_key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise RegistryError("invalid WireGuard peer public key") from exc
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != self.peer_public_key:
            raise RegistryError("non-canonical WireGuard peer public key")
        endpoint = _unicast_address(self.endpoint_address, "endpoint")
        source = _unicast_address(self.egress_source_address, "egress source")
        if endpoint.version != source.version:
            raise RegistryError("endpoint and egress source must share an address family")
        if endpoint.version != 4:
            raise RegistryError("the supported static underlay requires an IPv4 WireGuard endpoint")
        if type(self.endpoint_port) is not int or not 1 <= self.endpoint_port <= 65535:
            raise RegistryError("invalid host endpoint port")
        if not isinstance(self.tunnel_addresses, tuple) or len(self.tunnel_addresses) != 2:
            raise RegistryError("host protection requires exactly one IPv4 and one IPv6 tunnel address")
        try:
            tunnels = tuple(ipaddress.ip_interface(value) for value in self.tunnel_addresses)
        except (TypeError, ValueError) as exc:
            raise RegistryError("invalid host tunnel address") from exc
        if {item.version for item in tunnels} != {4, 6} or any(
            str(item) != value or item.ip.is_unspecified or item.ip.is_multicast
            for item, value in zip(tunnels, self.tunnel_addresses)
        ):
            raise RegistryError("host tunnel addresses must be canonical dual-stack unicast interfaces")
        if self.peer_allowed_ips != _REQUIRED_DEFAULTS:
            raise RegistryError("host peer allowed IPs must be canonical IPv4 and IPv6 defaults")
        if not isinstance(self.dns_servers, tuple) or not self.dns_servers:
            raise RegistryError("host protection requires pinned DNS servers")
        servers = tuple(_unicast_address(value, "DNS server") for value in self.dns_servers)
        if len(set(self.dns_servers)) != len(self.dns_servers) or any(
            str(server) != value for server, value in zip(servers, self.dns_servers)
        ):
            raise RegistryError("host DNS servers must be distinct canonical addresses")
        if not {4, 6} <= {server.version for server in servers}:
            raise RegistryError("host protection requires IPv4 and IPv6 DNS servers")
        for value, label, maximum in (
            (self.egress_ifindex, "egress interface index", 2**31 - 1),
            (self.route_table, "route table", 2**32 - 1),
            (self.endpoint_rule_priority, "endpoint rule priority", 32765),
            (self.tunnel_rule_priority, "tunnel rule priority", 32765),
            (self.fwmark, "WireGuard mark", 2**32 - 1),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise RegistryError(f"invalid host {label}")
        if self.endpoint_rule_priority >= self.tunnel_rule_priority:
            raise RegistryError("endpoint routing rule must precede the tunnel routing rule")
        if self.route_table in {253, 254, 255}:
            raise RegistryError("host protection requires a dedicated non-system route table")
        if self.resolver_mode != "systemd-resolved":
            raise RegistryError("only systemd-resolved host resolver ownership is supported")
        if self.firewall_family != "inet" or self.firewall_table != "nord_tools_host":
            raise RegistryError("host firewall identity must use the dedicated inet nord_tools_host table")
        if type(self.firewall_priority) is not int or not -300 <= self.firewall_priority <= -101:
            raise RegistryError("host firewall priority must precede ordinary filter chains")

    @classmethod
    def from_mapping(cls, document: object) -> "HostProtectionPlan":
        """Validate the exact public schema; unknown fields fail closed."""
        if not isinstance(document, Mapping):
            raise RegistryError("host protection plan must be a mapping")
        expected = {field.name for field in cls.__dataclass_fields__.values()}
        if set(document) != expected:
            missing = sorted(expected - set(document))
            unknown = sorted(set(document) - expected)
            raise RegistryError(f"host protection plan fields differ (missing={missing}, unknown={unknown})")
        values = dict(document)
        for field in ("tunnel_addresses", "dns_servers", "peer_allowed_ips"):
            if not isinstance(values[field], (list, tuple)):
                raise RegistryError(f"host protection {field} must be a list")
            values[field] = tuple(values[field])
        try:
            return cls(**values)
        except TypeError as exc:
            raise RegistryError("invalid host protection plan fields") from exc

    def public_plan(self) -> dict:
        """Return deterministic dry-run output without implying live authority."""
        document = asdict(self)
        document["tunnel_addresses"] = list(self.tunnel_addresses)
        document["dns_servers"] = list(self.dns_servers)
        document["peer_allowed_ips"] = list(self.peer_allowed_ips)
        return document

    def fingerprint(self) -> str:
        encoded = json.dumps(self.public_plan(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


def _unicast_address(value: object, label: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError) as exc:
        raise RegistryError(f"host {label} must be a numeric address") from exc
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
        or getattr(address, "ipv4_mapped", None) is not None
    ):
        raise RegistryError(f"host {label} is not a suitable unicast address")
    return address


def assess_host_default_protection(plan: object) -> dict:
    """Describe the minimum host protection requirements without changing state.

    Reject incomplete or ambiguous endpoint, DNS and dual-stack declarations.
    A caller cannot turn this assessment into permission to alter host routes.
    """
    if not isinstance(plan, Mapping):
        raise RegistryError("host default protection requires a tunnel plan mapping")
    required = {"endpoint_address", "endpoint_port", "tunnel_addresses", "peer_allowed_ips", "dns_servers"}
    if not required <= plan.keys():
        raise RegistryError("host default protection requires endpoint, tunnel, allowed IPs and DNS servers")
    try:
        endpoint = ipaddress.ip_address(plan["endpoint_address"])
        tunnels = tuple(ipaddress.ip_interface(value) for value in plan["tunnel_addresses"])
    except (ValueError, TypeError) as exc:
        raise RegistryError("host default protection requires numeric endpoint and tunnel addresses") from exc
    if endpoint.is_unspecified or endpoint.is_multicast or endpoint.is_loopback or endpoint.is_link_local:
        raise RegistryError("host default endpoint is unsuitable for a pinned underlay exception")
    if (
        len(tunnels) != 2
        or {tunnel.version for tunnel in tunnels} != {4, 6}
        or any(str(tunnel) != value for tunnel, value in zip(tunnels, plan["tunnel_addresses"], strict=True))
        or any(tunnel.ip.is_unspecified or tunnel.ip.is_multicast for tunnel in tunnels)
    ):
        raise RegistryError("host default tunnel addresses must be canonical dual-stack interfaces")
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
