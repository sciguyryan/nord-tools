"""Produce deterministic, non-executable per-application routing decisions.

Plans contain no namespace authority, process handles or permission to mutate the
host. A future privileged launcher must independently verify its own authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from nord_tools_internal.nordvpn_profiles import ProfileError, validate_policy

_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")


@dataclass(frozen=True)
class ApplicationRoutingPlan:
    application: str
    executable: str
    arguments: tuple[str, ...]
    profile: str
    sharing: str
    allocation_key: str
    inherited: bool


def plan_application(policy: dict, application: str, arguments: tuple[str, ...] = ()) -> ApplicationRoutingPlan:
    """Resolve an explicitly registered application without launching anything.

    Unknown applications are rejected: the default profile is an inheritance
    policy, not authority to launch arbitrary executables. An isolated profile
    has a distinct allocation key per application; a shared profile reuses one
    logical allocation key. Neither key is a kernel resource identifier.
    """
    checked = validate_policy(policy)
    if not isinstance(application, str) or not _NAME.fullmatch(application):
        raise ProfileError("application must be a valid registered name")
    app = checked["applications"].get(application)
    if app is None:
        raise ProfileError("application is not registered; no executable can be planned")
    if not isinstance(arguments, tuple) or any(not isinstance(arg, str) or "\x00" in arg for arg in arguments):
        raise ProfileError("arguments must be a tuple of strings without NUL bytes")
    profile = app["vpn"]
    sharing = checked["vpn_profiles"][profile]["sharing"]
    key = f"profile:{profile}" if sharing == "shared" else f"application:{application}:profile:{profile}"
    return ApplicationRoutingPlan(
        application=application,
        executable=app["executable"],
        arguments=arguments,
        profile=profile,
        sharing=sharing,
        allocation_key=key,
        inherited="vpn" not in policy["applications"][application],
    )
