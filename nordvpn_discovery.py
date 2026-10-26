"""Read-only Linux namespace and interface discovery for diagnostic comparison.

Kernel observations are not proof of Nord Tools ownership. This module never
changes networking, and it never treats an interface name as deletion authority.
"""

from __future__ import annotations

import json
import platform
import subprocess


class DiscoveryError(ValueError):
    """Live discovery could not be completed reliably."""


def _ip_json(*args: str, runner=subprocess.run) -> list[dict]:
    try:
        result = runner(["ip", "-j", *args], capture_output=True, text=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiscoveryError(f"ip command unavailable or timed out: {exc}") from exc
    if result.returncode != 0:
        raise DiscoveryError(f"ip {' '.join(args)} failed (exit {result.returncode}): {result.stderr.strip()[:200]}")
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise DiscoveryError("ip returned invalid JSON") from exc
    if not isinstance(data, list) or not all(isinstance(entry, dict) for entry in data):
        raise DiscoveryError("ip returned an unexpected JSON structure")
    return data


def _links(items: list[dict], scope: str) -> list[dict]:
    links = []
    for item in items:
        name, index = item.get("ifname"), item.get("ifindex")
        if not isinstance(name, str) or not name or type(index) is not int or index < 1:
            raise DiscoveryError(f"invalid interface identity in {scope}")
        links.append({"name": name, "index": index})
    if len({entry["name"] for entry in links}) != len(links) or len({entry["index"] for entry in links}) != len(links):
        raise DiscoveryError(f"duplicate interface identity in {scope}")
    return sorted(links, key=lambda entry: (entry["name"], entry["index"]))


def _routes(items: list[dict], scope: str) -> list[dict]:
    """Keep kernel route attributes as observations, never as ownership evidence."""
    routes = []
    for item in items:
        if not isinstance(item.get("dst"), str) or not item["dst"]:
            raise DiscoveryError(f"invalid route destination in {scope}")
        routes.append(item)
    return sorted(routes, key=lambda item: json.dumps(item, sort_keys=True))


def _nft_ruleset(*, namespace: str | None, runner=subprocess.run) -> list[dict]:
    """Observe nftables without interpreting rule ownership or effectiveness."""
    command = ["nft", "-j", "list", "ruleset"]
    if namespace is not None:
        command = ["ip", "netns", "exec", namespace, *command]
    try:
        result = runner(command, capture_output=True, text=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiscoveryError(f"nftables observation unavailable or timed out: {exc}") from exc
    if result.returncode != 0:
        raise DiscoveryError(f"nftables observation failed (exit {result.returncode}): {result.stderr.strip()[:200]}")
    try:
        payload = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise DiscoveryError("nft returned invalid JSON") from exc
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("nftables"), list)
        or not all(isinstance(entry, dict) for entry in payload["nftables"])
    ):
        raise DiscoveryError("nft returned an unexpected JSON structure")
    return payload["nftables"]


def discover(*, system=platform.system, runner=subprocess.run) -> dict:
    """Observe host and named-namespace interfaces and routes without mutations.

    A namespace may disappear during discovery. Any failed query aborts the
    entire observation instead of presenting incomplete results as complete.
    """
    if system() != "Linux":
        raise DiscoveryError("live discovery is supported on Linux only")
    namespaces = _ip_json("netns", "list", runner=runner)
    interfaces = _ip_json("link", "show", runner=runner)
    names = []
    for item in namespaces:
        name = item.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise DiscoveryError("invalid or duplicate namespace name in ip output")
        names.append(name)
    host_links = _links(interfaces, "host")
    host_routes = _routes(_ip_json("route", "show", "table", "all", runner=runner), "host")
    host_ipv6_routes = _routes(_ip_json("-6", "route", "show", "table", "all", runner=runner), "host")
    host_nftables = _nft_ruleset(namespace=None, runner=runner)
    namespace_details = []
    for name in sorted(names):
        # Pass the namespace as one argv element, never through a shell.
        namespace_details.append(
            {
                "name": name,
                "interfaces": _links(_ip_json("-n", name, "link", "show", runner=runner), name),
                "routes": _routes(_ip_json("-n", name, "route", "show", "table", "all", runner=runner), name),
                "ipv6_routes": _routes(
                    _ip_json("-n", name, "-6", "route", "show", "table", "all", runner=runner), name
                ),
                "nftables": _nft_ruleset(namespace=name, runner=runner),
            }
        )
    return {
        "schema_version": 1,
        "mode": "live_read_only",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_delete": False,
        "namespaces": sorted(names),
        "host_interfaces": host_links,
        "host_routes": host_routes,
        "host_ipv6_routes": host_ipv6_routes,
        "host_nftables": host_nftables,
        "namespace_details": namespace_details,
        "limitations": "Host and named-namespace links, IPv4/IPv6 routes and nftables rulesets; no DNS, services, firewall effectiveness or ownership verification",
    }
