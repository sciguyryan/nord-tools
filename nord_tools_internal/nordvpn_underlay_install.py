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
        raise UnderlayError(f"underlay step {argv[1:3]!r} could not complete") from exc
    if result.returncode:
        # Command output can reveal addressing details; keep the message plain.
        raise UnderlayError(f"underlay step {argv[1:3]!r} failed (exit {result.returncode})")


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
    tunnel_addresses: tuple[str, ...],
    host_gateway: str,
    *,
    runner=subprocess.run,
) -> None:
    """Route the protected default through the tunnel and the endpoint via underlay.

    A direct route to the peer endpoint keeps tunnel establishment reachable
    through the underlay. Both IPv4 and IPv6 default routes are pinned to the
    WireGuard device, even when only one family has a configured tunnel address.
    The other family may not be usable, but it must never gain an underlay
    default route. The namespace firewall remains the independent enforcement
    boundary for traffic and endpoint restrictions.
    """
    if not isinstance(tunnel_addresses, tuple) or not 1 <= len(tunnel_addresses) <= 2:
        raise RegistryError("tunnel addresses must contain one or two interfaces")
    endpoint = ipaddress.ip_address(endpoint_address)
    addresses = tuple(_canonical_address(address, "tunnel address") for address in tunnel_addresses)
    families = {ipaddress.ip_interface(address).version for address in addresses}
    if len(families) != len(addresses):
        raise RegistryError("tunnel addresses must use distinct address families")
    if endpoint.version not in families:
        raise RegistryError("one tunnel address must match the peer endpoint family")
    add_tunnel_route(namespace, namespace_interface, str(ipaddress.ip_network(endpoint)), host_gateway, runner=runner)
    # Do not let an absent tunnel address family acquire a host/underlay
    # fallback through a later resolver or application configuration change.
    _run(["ip", "-4", "-n", namespace, "route", "add", "default", "dev", tunnel_interface], runner)
    _run(["ip", "-6", "-n", namespace, "route", "add", "default", "dev", tunnel_interface], runner)


def verify_tunnel_route_readback(
    namespace: str,
    tunnel_interface: str,
    underlay_interface: str,
    endpoint_address: str,
    *,
    runner=subprocess.run,
) -> None:
    """Refuse activation unless both defaults and the endpoint route remain pinned.

    Readback is a provisioning snapshot, not a persistent guard against a
    separately privileged network administrator changing the routing table.
    The namespace firewall remains the independent packet confinement layer.
    """
    if not isinstance(namespace, str) or not _NAMESPACE.fullmatch(namespace):
        raise RegistryError("invalid namespace for route verification")
    tunnel = _canonical_interface(tunnel_interface, "tunnel interface")
    underlay = _canonical_interface(underlay_interface, "underlay interface")
    endpoint = ipaddress.ip_address(endpoint_address)

    def read(family: int) -> list[dict]:
        try:
            result = runner(
                ["ip", f"-{family}", "-j", "-n", namespace, "route", "show", "table", "main"],
                check=False,
                capture_output=True,
                timeout=_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UnderlayError("namespace route readback could not complete") from exc
        if result.returncode:
            raise UnderlayError("namespace route readback failed")
        try:
            routes = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise UnderlayError("namespace route readback was not valid JSON") from exc
        if not isinstance(routes, list) or any(not isinstance(item, dict) for item in routes):
            raise UnderlayError("namespace route readback was malformed")
        return routes

    for family in (4, 6):
        routes = read(family)
        defaults = [item for item in routes if item.get("dst") in ("default", "0.0.0.0/0", "::/0")]
        if len(defaults) != 1 or defaults[0].get("dev") != tunnel or defaults[0].get("gateway"):
            raise UnderlayError("namespace default route is not exclusively pinned to WireGuard")
        if family == endpoint.version:
            matches = []
            for item in routes:
                try:
                    network = ipaddress.ip_network(item.get("dst", ""), strict=False)
                except (ValueError, TypeError):
                    continue
                if network.version == family and endpoint in network:
                    matches.append((network.prefixlen, item))
            if not matches:
                raise UnderlayError("the peer endpoint has no explicit underlay route")
            longest = max(prefix for prefix, _ in matches)
            selected = [item for prefix, item in matches if prefix == longest]
            if len(selected) != 1 or selected[0].get("dev") != underlay:
                raise UnderlayError("the peer endpoint is not exclusively pinned to the underlay")
