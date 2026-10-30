"""Offline application session bookkeeping and namespace preflight requirements.

Sessions are logical records, not process handles or evidence of kernel ownership.
No operation in this module launches a process or mutates a namespace.
"""

from __future__ import annotations

from dataclasses import dataclass

from nord_tools_internal.nordvpn_application_binding import ApplicationBindingState, _validate_state
from nord_tools_internal.nordvpn_application_launch import ApplicationLaunchRequest
from nord_tools_internal.nordvpn_profiles import ProfileError


@dataclass(frozen=True)
class ApplicationSession:
    session_id: str
    application: str
    allocation_key: str
    profile: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class ApplicationSessionState:
    sessions: tuple[ApplicationSession, ...] = ()


@dataclass(frozen=True)
class ApplicationSessionTransition:
    action: str
    session_id: str
    allocation_users_before: int
    allocation_users_after: int
    state: ApplicationSessionState


def _sessions(state: ApplicationSessionState) -> dict[str, ApplicationSession]:
    if not isinstance(state, ApplicationSessionState) or not isinstance(state.sessions, tuple):
        raise ProfileError("invalid application session state")
    result: dict[str, ApplicationSession] = {}
    for session in state.sessions:
        if (
            not isinstance(session, ApplicationSession)
            or not isinstance(session.session_id, str)
            or not session.session_id
            or session.session_id in result
            or not isinstance(session.argv, tuple)
            or not session.argv
        ):
            raise ProfileError("duplicate or invalid application session")
        result[session.session_id] = session
    return result


def plan_session_start(
    state: ApplicationSessionState,
    bindings: ApplicationBindingState,
    request: ApplicationLaunchRequest,
    session_id: str,
) -> ApplicationSessionTransition:
    """Record a logical session only when its current binding matches exactly.

    The caller supplies a stable opaque identifier. It must not be interpreted
    as a PID, namespace identifier or permission to inspect or kill a process.
    """
    existing = _sessions(state)
    bound = _validate_state(bindings)
    if not isinstance(session_id, str) or not session_id or "\x00" in session_id:
        raise ProfileError("session identifier must be a non-empty string without NUL bytes")
    if not isinstance(request, ApplicationLaunchRequest) or request.namespace_authorised:
        raise ProfileError("expected an unauthorised offline launch request")
    binding = bound.get(request.application)
    if (
        binding is None
        or binding.allocation_key != request.allocation_key
        or binding.profile != request.profile
        or (binding.executable, *binding.arguments) != request.argv
    ):
        raise ProfileError("session request differs from current application binding")
    session = ApplicationSession(session_id, request.application, request.allocation_key, request.profile, request.argv)
    old = existing.get(session_id)
    if old is not None and old != session:
        raise ProfileError("session identifier already refers to a different request")
    before = sum(item.allocation_key == session.allocation_key for item in existing.values())
    if old is None:
        existing[session_id] = session
    next_state = ApplicationSessionState(tuple(existing[key] for key in sorted(existing)))
    return ApplicationSessionTransition(
        "reuse" if old is not None else "start", session_id, before, before + (old is None), next_state
    )


def plan_session_stop(state: ApplicationSessionState, session_id: str) -> ApplicationSessionTransition:
    """Forget a logical session without signalling processes or deleting resources."""
    existing = _sessions(state)
    if not isinstance(session_id, str) or session_id not in existing:
        raise ProfileError("unknown application session")
    session = existing.pop(session_id)
    after = sum(item.allocation_key == session.allocation_key for item in existing.values())
    return ApplicationSessionTransition(
        "stop",
        session_id,
        after + 1,
        after,
        ApplicationSessionState(tuple(existing[key] for key in sorted(existing))),
    )


def application_namespace_requirements() -> tuple[str, ...]:
    """Return mandatory checks for a future independently authorised launcher.

    These are requirements, not checks performed by this offline module.
    """
    return (
        "independent creation-time namespace ownership and live identity verification",
        "fail-closed IPv4 and IPv6 firewall and routing before process creation",
        "namespace-local DNS and explicit DNS bypass policy",
        "authorised executable identity and untrusted argument handling",
        "desktop environment, D-Bus, X11 and Wayland socket exposure review",
        "process exit, orphan and interrupted-launch reconciliation",
        "shared allocation isolation and dedicated profile separation",
    )
