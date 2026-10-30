"""Fail-closed offline preparation of application namespace launch requests.

A launch request is descriptive only. In particular, it is not an authority
capability, an executable command, or proof that a namespace exists or is safe.
"""

from __future__ import annotations

from dataclasses import dataclass

from nord_tools_internal.nordvpn_application_binding import ApplicationBindingState, _validate_state
from nord_tools_internal.nordvpn_application_plan import ApplicationRoutingPlan
from nord_tools_internal.nordvpn_profiles import ProfileError


@dataclass(frozen=True)
class ApplicationLaunchRequest:
    application: str
    allocation_key: str
    profile: str
    argv: tuple[str, ...]
    namespace_authorised: bool = False


def prepare_application_launch(
    state: ApplicationBindingState, plan: ApplicationRoutingPlan
) -> ApplicationLaunchRequest:
    """Prepare an immutable argv vector for an existing, exact logical binding.

    The caller must separately establish verified kernel ownership, a live
    fail-closed policy and an authorised execution context before launching.
    No shell command, namespace path or privileged action is produced here.
    """
    bindings = _validate_state(state)
    if not isinstance(plan, ApplicationRoutingPlan):
        raise ProfileError("a validated application routing plan is required")
    binding = bindings.get(plan.application)
    if binding is None:
        raise ProfileError("application has no active logical binding")
    if (
        binding.allocation_key != plan.allocation_key
        or binding.profile != plan.profile
        or binding.executable != plan.executable
        or binding.arguments != plan.arguments
    ):
        raise ProfileError("launch plan differs from the current application binding")
    if not isinstance(binding.executable, str) or not binding.executable.startswith("/"):
        raise ProfileError("application executable must be an absolute path")
    if "\x00" in binding.executable or any("\x00" in arg for arg in binding.arguments):
        raise ProfileError("application command contains a NUL byte")
    return ApplicationLaunchRequest(
        application=binding.application,
        allocation_key=binding.allocation_key,
        profile=binding.profile,
        argv=(binding.executable, *binding.arguments),
    )


def execute_application_launch(request: ApplicationLaunchRequest) -> None:
    """Refuse execution until a separately reviewed privileged executor exists."""
    if not isinstance(request, ApplicationLaunchRequest):
        raise ProfileError("invalid application launch request")
    raise ProfileError(
        "application execution is disabled until production namespace ownership and fail-closed verification"
    )
