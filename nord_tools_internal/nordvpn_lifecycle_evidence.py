"""Correlate lifecycle claims with live discovery without granting ownership authority."""

from __future__ import annotations

from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_registry import RegistryError


def inspect_live_lifecycle(journal: object, observation: object) -> dict:
    """Classify names and lifecycle drift using a complete read-only observation.

    Kernel names, interface indices and journal tokens are insufficient to prove
    provenance. This report must never be consumed as permission to mutate.
    """
    validated = validate_journal(journal)
    if (
        not isinstance(observation, dict)
        or observation.get("mode") != "live_read_only"
        or observation.get("network_changes_applied") is not False
    ):
        raise RegistryError("requires complete read-only Linux discovery evidence")
    namespaces = observation.get("namespaces")
    host = observation.get("host_interfaces")
    details = observation.get("namespace_details")
    if not isinstance(namespaces, list) or not isinstance(host, list) or not isinstance(details, list):
        raise RegistryError("incomplete discovery evidence")
    if any(not isinstance(name, str) or not name for name in namespaces) or len(namespaces) != len(set(namespaces)):
        raise RegistryError("invalid namespace observation")
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("name"), str)
        or not isinstance(item.get("interfaces"), list)
        for item in details
    ):
        raise RegistryError("invalid namespace details")
    if sorted(item["name"] for item in details) != sorted(namespaces):
        raise RegistryError("incomplete or duplicate namespace details")
    locations: dict[str, set[str]] = {}
    for scope, links in [("host", host), *[(item["name"], item["interfaces"]) for item in details]]:
        if any(
            not isinstance(link, dict) or not isinstance(link.get("name"), str) or not link["name"] for link in links
        ):
            raise RegistryError("invalid interface observation")
        names = [link["name"] for link in links]
        if len(names) != len(set(names)):
            raise RegistryError("duplicate interface observation")
        for name in names:
            locations.setdefault(name, set()).add(scope)
    states = {event["allocation_id"]: event["state"] for event in validated["events"]}
    findings = []
    for resource in validated["allocations"]["resources"]:
        kind, name = resource["kind"], resource["identifier"]
        state = states.get(resource["allocation_id"], "unrecorded")
        if kind == "namespace":
            finding = "name_observed_unverified" if name in namespaces else "name_missing"
        elif kind == "interface":
            scopes = locations.get(name, set())
            finding = (
                "name_missing" if not scopes else "ambiguous_scope" if len(scopes) > 1 else "name_observed_unverified"
            )
        else:
            finding = "unsupported_resource_kind"
        if finding == "name_missing" and state in {"active", "degraded", "retiring"}:
            finding = "possible_stale_lifecycle"
        elif finding == "name_observed_unverified" and state in {"retired", "failed"}:
            finding = "possible_orphan_or_name_reuse"
        findings.append(
            {
                "allocation_id": resource["allocation_id"],
                "kind": kind,
                "identifier": name,
                "lifecycle_state": state,
                "finding": finding,
            }
        )
    return {
        "mode": "live_read_only_lifecycle_correlation",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_modify": False,
        "safe_to_delete": False,
        "resources": findings,
    }
