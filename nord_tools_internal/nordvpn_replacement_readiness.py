"""Read-only live replacement gate for existing, verified VPN allocations.

This gate deliberately grants no cut-over or retirement authority. It refuses
unsettled ownership and active consumer leases before replacement preparation.
"""

from __future__ import annotations

from nord_tools_internal.nordvpn_allocation_profiles import expand_allocation_profiles
from nord_tools_internal.nordvpn_consumer_reference_store import locked_consumer_references
from nord_tools_internal.nordvpn_discovery import discover
from nord_tools_internal.nordvpn_execution_lock import lifecycle_execution_lock
from nord_tools_internal.nordvpn_live_apply import _read
from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_runtime_consumers import _read as read_leases
from nord_tools_internal.nordvpn_startup import validate_startup_config
from nord_tools_internal.nordvpn_state_reconcile import derive_actual_state, reconcile_desired


def assess_replacement_readiness(config: object, profile: str, lease_path: str, *, observe=None) -> dict:
    """Check current ownership and lease evidence without mutating networking.

    Locks are acquired in lifecycle-then-consumer order, matching provisioning
    and retirement. All decisions remain observations, never reusable authority.
    """
    validated = validate_startup_config(config)
    if not validated.get("intent"):
        raise RegistryError("replacement readiness requires a durable intent store")
    if not isinstance(profile, str) or not profile:
        raise RegistryError("replacement requires an explicit profile")
    if not isinstance(lease_path, str) or not lease_path.startswith("/"):
        raise RegistryError("replacement requires an absolute runtime consumer lease path")
    with lifecycle_execution_lock(validated["journal"]), locked_consumer_references(lease_path):
        policy = validate_policy(_read(validated["policy"]))
        desired, _ = expand_allocation_profiles(policy)
        if profile not in desired["vpn_profiles"]:
            raise RegistryError("replacement profile is not present in effective policy")
        journal = validate_journal(_read(validated["journal"]))
        bindings = _read(validated["bindings"])
        intents = _read(validated["intent"])
        preflight = preflight_ownership(journal, bindings, (observe or discover)(), intents)
        actual = derive_actual_state(journal, bindings, preflight)
        graph = _read(validated["graph"]) if validated["graph"] else None
        reconciliation = reconcile_desired(desired, actual, graph)
        leases = read_leases(lease_path, policy)
        decisions = [item for item in reconciliation["decisions"] if item["profile"] == profile]
        if len(decisions) != 1:
            raise RegistryError("replacement profile lacks an unambiguous reconciliation decision")
        active = [item["application"] for item in leases["leases"] if item["profile"] == profile]
        blockers = []
        if decisions[0]["action"] != "converged":
            blockers.append("profile_not_converged")
        if any(item["action"] != "converged" for item in reconciliation["decisions"] if item["profile"] != profile):
            blockers.append("other_profiles_not_converged")
        if preflight.get("operator_review_required") or reconciliation.get("unclaimed"):
            blockers.append("ownership_review_required")
        if reconciliation.get("unresolved_intents"):
            blockers.append("unresolved_operations")
        if active:
            blockers.append("active_consumer_leases")
        return {
            "schema_version": 1,
            "mode": "live_replacement_readiness",
            "profile": profile,
            "current_action": decisions[0]["action"],
            "leased_consumers": sorted(active),
            "blockers": blockers,
            "eligible_for_non_disruptive_preparation": not blockers,
            "safe_to_cut_over": False,
            "safe_to_retire_old": False,
            "network_changes_applied": False,
        }
