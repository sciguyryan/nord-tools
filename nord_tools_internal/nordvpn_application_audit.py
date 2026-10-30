"""Read-only consistency audit for the offline per-application routing model.

This audit cannot observe processes, namespaces, routing tables or firewall state.
A clean result is not permission to execute an application or retire a tunnel.
"""

from __future__ import annotations

from dataclasses import dataclass

from nord_tools_internal.nordvpn_application_binding import ApplicationBindingState, _validate_state
from nord_tools_internal.nordvpn_application_session import ApplicationSessionState, _sessions
from nord_tools_internal.nordvpn_profiles import ProfileError


@dataclass(frozen=True)
class ApplicationAllocationSummary:
    allocation_key: str
    profile: str
    binding_count: int
    session_count: int


@dataclass(frozen=True)
class ApplicationAuditReport:
    allocations: tuple[ApplicationAllocationSummary, ...]
    binding_count: int
    session_count: int
    production_authorised: bool = False


def audit_application_state(
    bindings: ApplicationBindingState, sessions: ApplicationSessionState
) -> ApplicationAuditReport:
    """Reject contradictory logical state, without making live-state claims.

    Sessions must still match their original binding exactly. Allocation keys
    may be shared only within the same profile. Results are sorted so audits
    remain deterministic regardless of the insertion order of input records.
    """
    bound = _validate_state(bindings)
    active = _sessions(sessions)
    allocations: dict[str, tuple[str, int, int]] = {}
    for binding in bound.values():
        prior = allocations.get(binding.allocation_key)
        if prior is not None and prior[0] != binding.profile:
            raise ProfileError("allocation key is shared across different profiles")
        allocations[binding.allocation_key] = (binding.profile, (prior[1] if prior else 0) + 1, 0)
    for session in active.values():
        binding = bound.get(session.application)
        if binding is None or (
            session.allocation_key != binding.allocation_key
            or session.profile != binding.profile
            or session.argv != (binding.executable, *binding.arguments)
        ):
            raise ProfileError("application session has no matching current binding")
        profile, binding_count, session_count = allocations[session.allocation_key]
        allocations[session.allocation_key] = (profile, binding_count, session_count + 1)
    return ApplicationAuditReport(
        tuple(ApplicationAllocationSummary(key, *allocations[key]) for key in sorted(allocations)),
        len(bound),
        len(active),
    )
