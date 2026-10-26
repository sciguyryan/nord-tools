"""Correlate offline ownership claims with read-only kernel observations.

Name matches are diagnostic evidence only, never proof of ownership or permission
for deletion. Unrecognised resource kinds remain explicitly unsupported.
"""

from __future__ import annotations

from nordvpn_registry import RegistryError, validate_registry


def correlate(registry: object, observation: object) -> dict:
    ledger = validate_registry(registry)
    if (
        not isinstance(observation, dict)
        or observation.get("mode") != "live_read_only"
        or observation.get("network_changes_applied") is not False
    ):
        raise RegistryError("expected a complete read-only discovery observation")
    namespaces = observation.get("namespaces")
    host_links = observation.get("host_interfaces")
    details = observation.get("namespace_details")
    if not isinstance(namespaces, list) or not isinstance(host_links, list) or not isinstance(details, list):
        raise RegistryError("discovery observation is missing required collections")
    if any(not isinstance(name, str) or not name for name in namespaces) or len(set(namespaces)) != len(namespaces):
        raise RegistryError("invalid namespace observations")
    if any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in host_links):
        raise RegistryError("invalid host interface observations")
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("name"), str)
        or not isinstance(item.get("interfaces"), list)
        for item in details
    ):
        raise RegistryError("invalid namespace detail observations")
    if set(namespaces) != {item["name"] for item in details} or len(details) != len(namespaces):
        raise RegistryError("incomplete or duplicate namespace details")
    links = {"host": {item["name"] for item in host_links}}
    if len(links["host"]) != len(host_links):
        raise RegistryError("duplicate host interfaces")
    for item in details:
        names = []
        for link in item["interfaces"]:
            if not isinstance(link, dict) or not isinstance(link.get("name"), str):
                raise RegistryError("invalid namespace interface observation")
            names.append(link["name"])
        if len(names) != len(set(names)):
            raise RegistryError("duplicate namespace interfaces")
        links[item["name"]] = set(names)
    findings = []
    for claim in sorted(ledger["resources"], key=lambda item: (item["profile"], item["kind"], item["identifier"])):
        kind, identifier = claim["kind"], claim["identifier"]
        if kind == "namespace":
            status = "name_observed" if identifier in namespaces else "name_missing"
        elif kind == "interface":
            # Explicit scope is required: interface names can recur in namespaces.
            # The legacy unqualified claim is ambiguous and cannot be matched.
            scope, sep, name = identifier.partition(":")
            if not sep or not name or scope not in links:
                status = "ambiguous_or_unknown_scope"
            else:
                status = "name_observed" if name in links[scope] else "name_missing"
        else:
            status = "unsupported_evidence_kind"
        findings.append({**claim, "evidence": status})
    return {
        "schema_version": 1,
        "mode": "read_only_correlation",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_delete": False,
        "findings": findings,
    }
