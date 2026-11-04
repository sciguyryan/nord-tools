"""Read-only allocation ownership groups for registered applications.

These groups describe logical consumers, not kernel resources or permission to
create, share, retain or delete a tunnel. Privileged lifecycle operations must
establish their own verified ownership and reference evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from nord_tools_internal.nordvpn_application_plan import plan_application
from nord_tools_internal.nordvpn_profiles import validate_policy


@dataclass(frozen=True)
class OwnershipGroup:
    allocation_key: str
    profile: str
    sharing: str
    consumers: tuple[str, ...]


def resolve_ownership_groups(policy: dict) -> tuple[OwnershipGroup, ...]:
    """Group registered consumers deterministically without allocating resources.

    Shared profiles have one logical group per profile; isolated profiles have
    one group per registered application. Unused profiles do not imply a live
    consumer or permission to retire an existing resource.
    """
    checked = validate_policy(policy)
    groups: dict[str, tuple[str, str, list[str]]] = {}
    for application in sorted(checked["applications"]):
        plan = plan_application(policy, application)
        existing = groups.get(plan.allocation_key)
        if existing is None:
            groups[plan.allocation_key] = (plan.profile, plan.sharing, [application])
        else:
            profile, sharing, consumers = existing
            if (profile, sharing) != (plan.profile, plan.sharing):
                raise ValueError("logical ownership key collision")
            consumers.append(application)
    return tuple(
        OwnershipGroup(key, profile, sharing, tuple(consumers))
        for key, (profile, sharing, consumers) in sorted(groups.items())
    )
