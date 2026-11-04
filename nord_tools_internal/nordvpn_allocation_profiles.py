"""Stable, collision-checked kernel profile identities for consumer allocations.

The existing journal and owner bindings identify resources by profile. Isolated
consumers therefore need distinct *kernel* profile identities, rather than
merely different planning keys. No application is launched by this module.
"""

from __future__ import annotations

import hashlib

from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_sharing_contract import resolve_ownership_groups
from nord_tools_internal.nordvpn_registry import RegistryError


def kernel_profile_for_allocation(allocation_key: str, profile: str, sharing: str) -> str:
    """Return the journal identity of one logical allocation."""
    if sharing == "shared":
        return profile
    if sharing != "isolated" or not allocation_key.startswith("application:"):
        raise RegistryError("invalid isolated allocation identity")
    # The full logical key is bound into the digest; do not embed user-controlled
    # names in privileged kernel resource identifiers.
    return "ntiso_" + hashlib.sha256(allocation_key.encode("utf-8")).hexdigest()[:32]


def expand_allocation_profiles(policy: dict) -> tuple[dict, dict[str, str]]:
    """Expand isolated consumers into independently journalled profile instances.

    Returns a validated effective policy and an effective-to-provider profile
    mapping. The original policy is not modified. The expansion must be used
    consistently by restoration, reconciliation and selected retirement.
    """
    checked = validate_policy(policy)
    profiles = {name: dict(value) for name, value in checked["vpn_profiles"].items() if value["sharing"] == "shared"}
    used_isolated = {group.profile for group in resolve_ownership_groups(checked) if group.sharing == "isolated"}
    # An unused isolated profile remains a named, provisionable profile for
    # existing explicit profile management. Once it has consumers, those
    # consumers receive separate resources instead of the template resource.
    for name in sorted(set(checked["vpn_profiles"]) - set(profiles) - used_isolated):
        profiles[name] = dict(checked["vpn_profiles"][name])
    provider = {name: name for name in profiles}
    applications = {name: dict(value) for name, value in checked["applications"].items()}
    for group in resolve_ownership_groups(checked):
        if group.sharing != "isolated":
            continue
        identity = kernel_profile_for_allocation(group.allocation_key, group.profile, group.sharing)
        if identity in profiles or identity in checked["vpn_profiles"]:
            raise RegistryError("kernel allocation profile identity collision")
        profiles[identity] = dict(checked["vpn_profiles"][group.profile])
        provider[identity] = group.profile
        for application in group.consumers:
            applications[application]["vpn"] = identity
    effective = validate_policy(
        {
            "version": 1,
            "defaults": dict(checked["defaults"]),
            "vpn_profiles": profiles,
            "applications": applications,
        }
    )
    return effective, provider
