"""Restricted underlay wiring for one Nord Tools-owned network namespace.

This module creates a single virtual Ethernet pair between the host and an
already-created, descriptor-bound namespace, gives both ends the addresses the
provider tunnel plan specifies, and adds only the routes that tunnel
establishment requires. It never flushes or rewrites existing host firewall or
routing configuration: it creates and removes only its own interfaces, and
route insertion is confined to the namespace. The host end still needs ordinary
forwarding toward the internet before tunnel packets can leave the host; that
host-level requirement is verified and reported, never silently assumed.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess

from nord_tools_internal.nordvpn_registry import RegistryError

_TIMEOUT = 15
_INTERFACE = re.compile(r"[a-zA-Z0-9_.-]{1,15}\Z")
_NAMESPACE = re.compile(r"nt-[a-z0-9]{8,24}\Z")


class UnderlayError(RuntimeError):
    """Underlay wiring failed and the namespace cannot be used safely."""


def _run(argv: list[str], runner=subprocess.run) -> None:
    try:
        result = runner(argv, check=False, capture_output=True, timeout=_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UnderlayError("an underlay wiring command could not complete") from exc
    if result.returncode:
        # Command output can reveal addressing details; keep the message plain.
        raise UnderlayError("an underlay wiring command failed")


def _canonical_interface(name: object, field: str) -> str:
    if not isinstance(name, str) or not _INTERFACE.fullmatch(name):
        raise RegistryError(f"{field} must be a Linux interface name of at most 15 characters")
    return name


def _canonical_address(value: object, field: str) -> str:
    try:
        interface = ipaddress.ip_interface(str(value))
    except (TypeError, ValueError) as exc:
        raise RegistryError(f"{field} must be an IP address with prefix length") from exc
    if interface.ip.is_unspecified or interface.ip.is_multicast:
        raise RegistryError(f"{field} must be a routable unicast address with prefix length")
    return str(interface)


def _link_index_observed(index_choice: dict) -> int:
    if (
        not isinstance(index_choice, dict)
        or not isinstance(index_choice.get("ifindex"), int)
        or index_choice["ifindex"] < 1
    ):
        raise RegistryError("invalid interface observation inside the namespace")
    return index_choice["ifindex"]


def _namespace_links(namespace: str) -> dict[str, dict]:
    try:
        result = subprocess.run(
            ["ip", "-j", "-n", namespace, "link"], check=False, capture_output=True, timeout=_TIMEOUT
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UnderlayError("the namespace link listing could not complete") from exc
    if result.returncode:
        raise UnderlayError("the namespace link listing failed")
    try:
        links = json.loads(result.stdout)
    except ValueError as exc:
        raise RegistryError("invalid namespace link listing") from exc
    if not isinstance(links, list):
        raise RegistryError("invalid namespace link listing")
    return {item["ifname"]: item for item in links if isinstance(item, dict) and isinstance(item.get("ifname"), str)}


def install_namespace_underlay(
    namespace: str,
    namespace_interface: str,
    host_interface: str,
    namespace_address: str,
    host_address: str,
    *,
    runner=subprocess.run,
) -> int:
    """Create, address and raise one host-to-namespace virtual Ethernet pair.

    Returns the namespace-local interface index for the interface binding. Any
    failure attempts to remove only what this call created; an uncertain partial
    state is left for operator review and reported, never guessed around.
    """
    ns_iface = _canonical_interface(namespace_interface, "namespace underlay interface")
    host_iface = _canonical_interface(host_interface, "host underlay interface")
    if not isinstance(namespace, str) or not _NAMESPACE.fullmatch(namespace):
        raise RegistryError("the ownable namespace name must match nt-[a-z0-9]{8,24}")
    if ns_iface == host_iface:
        raise RegistryError("host and namespace underlay interface names must differ")
    addresses = (
        _canonical_address(namespace_address, "namespace underlay address"),
        _canonical_address(host_address, "host underlay address"),
    )
    _run(["ip", "link", "add", host_iface, "type", "veth", "peer", "name", ns_iface], runner)
    try:
        _run(["ip", "link", "set", ns_iface, "netns", namespace], runner)
        _run(["ip", "address", "add", addresses[1], "dev", host_iface], runner)
        _run(["ip", "netns", "exec", namespace, "ip", "address", "add", addresses[0], "dev", ns_iface], runner)
        _run(["ip", "link", "set", host_iface, "up"], runner)
        _run(["ip", "netns", "exec", namespace, "ip", "link", "set", ns_iface, "up"], runner)
        links = _namespace_links(namespace)
        if ns_iface not in links:
            raise UnderlayError("the underlay interface is absent from the namespace after wiring")
        return _link_index_observed(links[ns_iface])
    except BaseException:
        # Remove our own pair best effort; delegate any remaining uncertainty to
        # the operator rather than deleting an interface we cannot identify.
        try:
            _run(["ip", "link", "del", "dev", host_iface], runner)
        except UnderlayError:
            pass
        raise


def namespace_interface_index(namespace: str, interface: str) -> int:
    """Return the current namespace-local index for an observed interface name."""
    if not isinstance(namespace, str) or not _NAMESPACE.fullmatch(namespace):
        raise RegistryError("the ownable namespace name must match nt-[a-z0-9]{8,24}")
    if not isinstance(interface, str) or not _INTERFACE.fullmatch(interface):
        raise RegistryError("invalid WireGuard interface name")
    links = _namespace_links(namespace)
    if interface not in links:
        raise UnderlayError(f"interface {interface} is absent from namespace {namespace}")
    return _link_index_observed(links[interface])


def add_tunnel_route(
    namespace: str, tunnel_interface: str, destination: str, via: str, *, runner=subprocess.run
) -> None:
    """Add one IPv4 route inside the namespace via the tunnel or underlay.

    Only additions are performed. The namespace firewall limits what may flow;
    routing here decides where permitted packets go, never what is permitted.
    """
    tunnel = _canonical_interface(tunnel_interface, "tunnel interface")
    network = ipaddress.ip_network(destination, strict=False)
    gateway = ipaddress.ip_address(via)
    if network.version != gateway.version:
        raise RegistryError("route destination and gateway must share one address family")
    _run(
        [
            "ip",
            "-n",
            namespace,
            "route",
            "add",
            str(network),
            "via",
            str(gateway),
            "dev",
            tunnel,
        ],
        runner,
    )


def install_tunnel_routing(
    namespace: str,
    tunnel_interface: str,
    namespace_interface: str,
    endpoint_address: str,
    tunnel_address: str,
    host_gateway: str,
    *,
    runner=subprocess.run,
) -> None:
    """Route the protected default through the tunnel and the endpoint via underlay.

    A direct route to the peer endpoint keeps tunnel establishment reachable
    through the underlay while everything else defaults to the tunnel. A
    single-family default route is installed for the tunnel address family; the
    IPv6 confinement programme's real-tunnel acceptance remains outstanding, so
    no IPv6 route is invented here beyond the family of the tunnel address.
    """
    tunnel_ip = _canonical_address(tunnel_address, "tunnel address")
    endpoint = ipaddress.ip_address(endpoint_address)
    if endpoint.version != ipaddress.ip_interface(tunnel_ip).version:
        raise RegistryError("the tunnel address family must match the peer endpoint family")
    add_tunnel_route(namespace, namespace_interface, str(ipaddress.ip_network(endpoint)), host_gateway, runner=runner)
    _run(["ip", "-n", namespace, "route", "add", "default", "dev", tunnel_interface], runner)
