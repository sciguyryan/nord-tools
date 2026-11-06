"""Conservative consumer-reference decisions for logical tunnel ownership.

These decisions cannot authorise kernel mutation. The ownership-aware cleanup
executor must still verify its own creation-time resource bindings.
"""

from __future__ import annotations

from dataclasses import dataclass

from nord_tools_internal.nordvpn_profiles import ProfileError, validate_policy
from nord_tools_internal.nordvpn_sharing_contract import resolve_ownership_groups


@dataclass(frozen=True)
class ReferenceDecision:
    allocation_key: str
    profile: str
    sharing: str
    retained_consumers: tuple[str, ...]
    released_consumers: tuple[str, ...]
    retirement_eligible: bool


def plan_consumer_release(policy: dict, released: tuple[str, ...]) -> tuple[ReferenceDecision, ...]:
    """Evaluate an explicit consumer release against the complete policy.

    An empty retained reference set permits *consideration* of retirement, not
    deletion. A caller must never infer kernel authority from this result.
    """
    checked = validate_policy(policy)
    if (
        not isinstance(released, tuple)
        or any(not isinstance(name, str) or name not in checked["applications"] for name in released)
        or len(set(released)) != len(released)
    ):
        raise ProfileError("released consumers must be distinct registered application names")
    if any(checked["applications"][name]["vpn"] == "direct" for name in released):
        raise ProfileError("direct applications have no VPN consumer references to release")
    selected = set(released)
    decisions = []
    for group in resolve_ownership_groups(checked):
        retained = tuple(name for name in group.consumers if name not in selected)
        removed = tuple(name for name in group.consumers if name in selected)
        decisions.append(
            ReferenceDecision(group.allocation_key, group.profile, group.sharing, retained, removed, not retained)
        )
    return tuple(decisions)
