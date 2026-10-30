"""Offline application-to-allocation binding and lifecycle planning.

This module models references, not processes or kernel resources. A binding
never establishes namespace ownership or permission to launch an executable.
"""

from __future__ import annotations

from dataclasses import dataclass

from nord_tools_internal.nordvpn_application_plan import ApplicationRoutingPlan
from nord_tools_internal.nordvpn_profiles import ProfileError


@dataclass(frozen=True)
class ApplicationBinding:
    application: str
    allocation_key: str
    profile: str
    executable: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class ApplicationBindingState:
    bindings: tuple[ApplicationBinding, ...] = ()


@dataclass(frozen=True)
class ApplicationBindingTransition:
    action: str
    application: str
    allocation_key: str
    allocation_users_before: int
    allocation_users_after: int
    state: ApplicationBindingState


def _validate_state(state: ApplicationBindingState) -> dict[str, ApplicationBinding]:
    if not isinstance(state, ApplicationBindingState) or not isinstance(state.bindings, tuple):
        raise ProfileError("invalid application binding state")
    found: dict[str, ApplicationBinding] = {}
    for binding in state.bindings:
        if not isinstance(binding, ApplicationBinding) or binding.application in found:
            raise ProfileError("duplicate or invalid application binding")
        if not binding.application or not binding.allocation_key or not binding.profile or not binding.executable:
            raise ProfileError("incomplete application binding")
        found[binding.application] = binding
    return found


def plan_binding(state: ApplicationBindingState, plan: ApplicationRoutingPlan) -> ApplicationBindingTransition:
    """Bind one registered application without creating or modifying resources.

    Rebinding an application to different arguments or policy requires an
    explicit unbind first. This prevents a stale binding being silently reused.
    """
    existing = _validate_state(state)
    if not isinstance(plan, ApplicationRoutingPlan):
        raise ProfileError("a validated application routing plan is required")
    binding = ApplicationBinding(plan.application, plan.allocation_key, plan.profile, plan.executable, plan.arguments)
    old = existing.get(plan.application)
    if old is not None and old != binding:
        raise ProfileError("application binding differs; unbind before replanning")
    before = sum(item.allocation_key == binding.allocation_key for item in existing.values())
    if old is None:
        existing[plan.application] = binding
    next_state = ApplicationBindingState(tuple(existing[name] for name in sorted(existing)))
    return ApplicationBindingTransition(
        "reuse" if old is not None else "bind",
        plan.application,
        binding.allocation_key,
        before,
        before + (old is None),
        next_state,
    )


def plan_unbinding(state: ApplicationBindingState, application: str) -> ApplicationBindingTransition:
    """Release a logical application reference, never a kernel allocation."""
    existing = _validate_state(state)
    if not isinstance(application, str) or application not in existing:
        raise ProfileError("application has no binding")
    binding = existing.pop(application)
    after = sum(item.allocation_key == binding.allocation_key for item in existing.values())
    next_state = ApplicationBindingState(tuple(existing[name] for name in sorted(existing)))
    return ApplicationBindingTransition("unbind", application, binding.allocation_key, after + 1, after, next_state)
