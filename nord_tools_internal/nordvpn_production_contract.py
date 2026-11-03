"""Read-only production provisioning contract for named WireGuard profiles.

This boundary checks policy, tunnel plans and candidate allocations together.
It neither supplies credentials nor authorises kernel mutation. Privileged
executors must still obtain the lifecycle lock, verify creation-time ownership
and record a durable operation intent immediately before each mutation.
"""

from __future__ import annotations

from collections.abc import Mapping

from nord_tools_internal.nordvpn_identity import validate_allocations
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification


def validate_provisioning_contract(policy: object, tunnels: object, allocations: object) -> dict:
    """Validate complete, distinct profile-to-tunnel and candidate identity mappings.

    Missing plans and extraneous resources are refused rather than implicitly
    adopting a previously existing interface or namespace. Allocation tokens
    are descriptive correlation identifiers, not proof of kernel ownership.
    """
    checked = validate_policy(policy)
    if not isinstance(tunnels, Mapping) or set(tunnels) != set(checked["vpn_profiles"]):
        raise RegistryError("tunnel plans must name exactly the configured VPN profiles")
    ledger = validate_allocations(allocations)
    by_profile: dict[str, dict[str, str]] = {}
    for entry in ledger["resources"]:
        profile = entry["profile"]
        if profile not in checked["vpn_profiles"]:
            raise RegistryError("allocation names an unknown VPN profile")
        if entry["kind"] not in ("namespace", "interface"):
            raise RegistryError("provisioning contract supports only namespaces and interfaces")
        owned = by_profile.setdefault(profile, {})
        if entry["kind"] in owned:
            raise RegistryError("profile has duplicate candidate resources of the same kind")
        owned[entry["kind"]] = entry["identifier"]

    validated_tunnels = {}
    for profile, specification in tunnels.items():
        if not isinstance(specification, TunnelSpecification):
            raise RegistryError("tunnel plan must be a validated TunnelSpecification")
        expected = {"namespace": specification.namespace, "interface": specification.interface}
        if by_profile.get(profile) != expected:
            raise RegistryError("tunnel plan and candidate allocation identities disagree")
        validated_tunnels[profile] = specification.public_plan()

    return {
        "version": 1,
        "mode": "offline_production_provisioning_contract",
        "network_changes_applied": False,
        "ownership_verified": False,
        "mutation_authorised": False,
        "default_profile": checked["defaults"]["vpn"],
        "profiles": {
            name: {
                "sharing": checked["vpn_profiles"][name]["sharing"],
                "tunnel": validated_tunnels[name],
            }
            for name in sorted(validated_tunnels)
        },
    }


def validate_provisioning_owner_bindings(
    policy: object, tunnels: object, allocations: object, bindings: object
) -> dict:
    """Correlate recorded creation identities with the complete proposed plan.

    This is a read-only evidence consistency check, not a live ownership
    inspection. Even matching records require fresh privileged verification,
    lifecycle locking and durable intents at the mutation boundary.
    """
    from nord_tools_internal.nordvpn_ownership_verify import validate_bindings

    contract = validate_provisioning_contract(policy, tunnels, allocations)
    ledger = validate_allocations(allocations)
    recorded = validate_bindings(bindings)
    expected = {item["allocation_id"]: (item["kind"], item["identifier"]) for item in ledger["resources"]}
    actual = {item["allocation_id"]: (item["kind"], item["identifier"]) for item in recorded["bindings"]}
    if actual != expected:
        raise RegistryError("creation-time owner bindings do not match the complete provisioning allocation ledger")
    return {
        **contract,
        "mode": "offline_production_provisioning_owner_correlation",
        "recorded_bindings_consistent": True,
        "recorded_binding_count": len(actual),
    }
