"""Conservative offline replacement staging and cut-over obligations.

A proposed cut-over is never authority to mutate a real namespace or tunnel.
"""

from __future__ import annotations

from collections.abc import Mapping


class ReplacementStageError(ValueError):
    """A replacement plan has an ambiguous or unsafe logical dependency."""


def plan_staged_replacement(current: object, proposed: object, dependents: object, verification: object) -> dict:
    """Describe an isolated replacement without changing existing assignments.

    The caller supplies untrusted logical snapshots. Verification flags are only
    planning hints, never privileged evidence or ownership proof.
    """
    if not isinstance(current, Mapping) or not isinstance(proposed, Mapping):
        raise ReplacementStageError("current and proposed must be mappings")
    if set(current) != {"profile", "allocation"} or set(proposed) != {"profile", "allocation"}:
        raise ReplacementStageError("replacement requires exact profile and allocation fields")
    profile = current["profile"]
    old = current["allocation"]
    new = proposed["allocation"]
    if any(not isinstance(value, str) or not value.strip() for value in (profile, old, new)):
        raise ReplacementStageError("profile and allocations must be nonempty strings")
    if proposed["profile"] != profile:
        raise ReplacementStageError("replacement cannot change profile identity")
    if old == new:
        raise ReplacementStageError("replacement requires a distinct staged allocation")
    if (
        not isinstance(dependents, (list, tuple))
        or any(not isinstance(item, str) or not item.strip() for item in dependents)
        or len(dependents) != len(set(dependents))
    ):
        raise ReplacementStageError("dependents must be unique nonempty application identifiers")
    if (
        not isinstance(verification, Mapping)
        or set(verification) != {"tunnel", "dns", "firewall"}
        or any(type(value) is not bool for value in verification.values())
    ):
        raise ReplacementStageError("verification requires exact Boolean tunnel, dns and firewall fields")
    verified = all(verification.values())
    return {
        "schema_version": 1,
        "mode": "offline_staged_replacement",
        "profile": profile,
        "existing_allocation": old,
        "staged_allocation": new,
        "preserved_dependents": sorted(dependents),
        "stages": [
            "verify_independent_creation_time_ownership",
            "prepare_distinct_isolated_allocation",
            "install_fail_closed_firewall_and_resolver",
            "verify_real_tunnel_dns_and_endpoint",
            "atomically_switch_only_profile_dependents",
            "verify_cutover_and_retire_independently_owned_old_allocation",
        ],
        "reported_checks_complete": verified,
        "next_planning_obligation": (
            "fresh_privileged_ownership_and_atomic_cutover_validation"
            if verified
            else "verify_staged_tunnel_dns_and_firewall"
        ),
        "existing_assignment_preserved": True,
        "unaffected_profiles_preserved": True,
        "requires_privileged_reverification": True,
        "requires_crash_persistent_ownership": True,
        "safe_to_cut_over": False,
        "safe_to_retire_old": False,
        "network_changes_applied": False,
    }
