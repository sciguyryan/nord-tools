"""Compare recorded kernel identity snapshots with read-only observations.

Snapshots are diagnostics, not ownership attestations. Kernel interface indices
and namespace names can be reused, so even an exact match grants no authority.
"""

from __future__ import annotations

from nordvpn_lifecycle import validate_journal
from nordvpn_registry import RegistryError


def compare_fingerprints(journal: object, recorded: object, observation: object) -> dict:
    """Report identity drift without interpreting matches as permission to act."""
    validated = validate_journal(journal)
    if (
        not isinstance(recorded, dict)
        or set(recorded) != {"version", "resources"}
        or type(recorded["version"]) is not int
        or recorded["version"] != 1
        or not isinstance(recorded["resources"], list)
    ):
        raise RegistryError("invalid resource fingerprint snapshot")
    if (
        not isinstance(observation, dict)
        or observation.get("mode") != "live_read_only"
        or observation.get("network_changes_applied") is not False
    ):
        raise RegistryError("requires read-only discovery")
    host = observation.get("host_interfaces")
    details = observation.get("namespace_details")
    namespaces = observation.get("namespaces")
    if (
        not isinstance(host, list)
        or not isinstance(details, list)
        or not isinstance(namespaces, list)
        or len(namespaces) != len(set(namespaces))
    ):
        raise RegistryError("incomplete discovery")
    if any(not isinstance(name, str) or not name for name in namespaces):
        raise RegistryError("invalid namespace list")
    if any(
        not isinstance(item, dict)
        or set(item) < {"name", "interfaces"}
        or not isinstance(item["name"], str)
        or not isinstance(item["interfaces"], list)
        for item in details
    ):
        raise RegistryError("invalid namespace details")
    if sorted(item["name"] for item in details) != sorted(namespaces):
        raise RegistryError("incomplete namespace observation")
    current = {}
    for scope, links in [("host", host), *[(item["name"], item["interfaces"]) for item in details]]:
        for link in links:
            if (
                not isinstance(link, dict)
                or not isinstance(link.get("name"), str)
                or not link["name"]
                or type(link.get("index")) is not int
                or link["index"] < 1
            ):
                raise RegistryError("invalid observed interface identity")
            key = (scope, link["name"])
            if key in current or any(
                index == link["index"] for (other_scope, _), index in current.items() if other_scope == scope
            ):
                raise RegistryError("duplicate observed interface identity")
            current[key] = link["index"]
    allocations = {item["allocation_id"]: item for item in validated["allocations"]["resources"]}
    seen = set()
    results = []
    for entry in recorded["resources"]:
        if not isinstance(entry, dict) or set(entry) != {"allocation_id", "scope", "ifindex"}:
            raise RegistryError("invalid fingerprint fields")
        token, scope, index = entry["allocation_id"], entry["scope"], entry["ifindex"]
        if (
            token not in allocations
            or token in seen
            or allocations[token]["kind"] != "interface"
            or not isinstance(scope, str)
            or not scope
            or type(index) is not int
            or index < 1
        ):
            raise RegistryError("invalid fingerprint identity")
        seen.add(token)
        name = allocations[token]["identifier"]
        if scope != "host" and scope not in namespaces:
            finding = "scope_missing"
        elif (scope, name) not in current:
            finding = "interface_missing"
        elif current[(scope, name)] != index:
            finding = "interface_index_changed"
        else:
            finding = "fingerprint_matches_unverified"
        results.append(
            {
                "allocation_id": token,
                "scope": scope,
                "identifier": name,
                "recorded_ifindex": index,
                "observed_ifindex": current.get((scope, name)),
                "finding": finding,
            }
        )
    return {
        "mode": "read_only_fingerprint_comparison",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_modify": False,
        "safe_to_delete": False,
        "resources": results,
    }
