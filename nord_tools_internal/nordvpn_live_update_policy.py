"""Non-mutating update policy for freshly reconciled production allocations."""

from __future__ import annotations

from nord_tools_internal.nordvpn_allocation_profiles import (
    expand_allocation_profiles,
    kernel_profile_for_allocation,
)
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_sharing_contract import resolve_ownership_groups


_ACTIONS = {
    "blocked",
    "configuration_changed",
    "configuration_unverified",
    "converged",
    "create_pending",
    "retire_pending",
}


def classify_live_updates(policy: object, decisions: object) -> dict:
    """Map fresh reconciliation outcomes onto existing explicit authorities.

    Live allocations are immutable. This report never authorises mutation; it
    tells the caller which already-supported lifecycle owns the next step.
    """
    checked = validate_policy(policy)
    effective, sources = expand_allocation_profiles(checked)
    if not isinstance(decisions, list):
        raise RegistryError("live update classification requires reconciliation decisions")
    allocation_keys = {
        kernel_profile_for_allocation(group.allocation_key, group.profile, group.sharing): group.allocation_key
        for group in resolve_ownership_groups(checked)
    }
    for name, definition in effective["vpn_profiles"].items():
        if definition["sharing"] == "shared":
            allocation_keys.setdefault(name, f"profile:{sources[name]}")
    updates = []
    seen = set()
    for decision in decisions:
        if (
            not isinstance(decision, dict)
            or not isinstance(decision.get("profile"), str)
            or decision.get("action") not in _ACTIONS
            or decision["profile"] in seen
        ):
            raise RegistryError("live update classification received an invalid or duplicate decision")
        profile = decision["profile"]
        action = decision["action"]
        seen.add(profile)
        logical = sources.get(profile)
        allocation_key = allocation_keys.get(profile)
        if action == "converged":
            strategy, authority = "none", "none"
        elif action == "create_pending":
            strategy, authority = "create_absent", "apply-live --execute"
        elif action == "retire_pending":
            strategy, authority = "verified_retirement", "retire-consumers or cleanup --execute"
        elif action == "configuration_changed" and logical is not None and allocation_key is not None:
            strategy, authority = "generation_replacement", "replace-profile --execute"
        else:
            strategy, authority = "operator_review", "no mutation authorised"
        entry = {
            "profile": profile,
            "logical_profile": logical,
            "reconciliation_action": action,
            "strategy": strategy,
            "authority": authority,
            "in_place_mutation_authorised": False,
        }
        if strategy == "generation_replacement":
            entry["replacement_inputs"] = {
                "profile": logical,
                "allocation_key": allocation_key,
                "operator_must_choose": [
                    "old_generation",
                    "replacement_generation",
                    "runtime_consumers",
                ],
            }
        updates.append(entry)
    return {
        "schema_version": 1,
        "mode": "immutable_live_update_policy",
        "network_changes_applied": False,
        "in_place_updates_supported": False,
        "automatic_provider_reselection_supported": False,
        "startup_configuration_changes_require_explicit_replacement": True,
        "allocation_model": "immutable_generation",
        "updates": updates,
        "limitations": (
            "Configuration-unverified or blocked allocations require operator review. "
            "This policy does not repair drift or authorise mutation from a read-only observation."
        ),
    }
