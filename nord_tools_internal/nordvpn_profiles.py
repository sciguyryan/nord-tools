"""Validate VPN routing intent without performing privileged networking operations."""

from __future__ import annotations

import re

from nordvpn_connection import normalise_server_identity
from nordvpn_filter import compile_filter
from nordvpn_regions import normalise_country_code


class ProfileError(ValueError):
    """A profile cannot be interpreted without ambiguity."""


def _mapping(value, name):
    if not isinstance(value, dict):
        raise ProfileError(f"{name} must be an object")
    return value


def _keys(value, allowed, name):
    unknown = set(value) - set(allowed)
    if unknown:
        raise ProfileError(f"{name} has unknown keys: {', '.join(sorted(map(str, unknown)))}")


def validate_policy(policy):
    """Return a normalised, detached policy; reject ambiguous routing assignments.

    This is a policy *description*, not proof that a tunnel or kill switch exists.
    """
    root = _mapping(policy, "policy")
    _keys(root, {"version", "defaults", "vpn_profiles", "applications"}, "policy")
    if type(root.get("version")) is not int or root["version"] != 1:
        raise ProfileError("policy.version must be 1")
    defaults = _mapping(root.get("defaults"), "defaults")
    _keys(defaults, {"vpn"}, "defaults")
    profiles = _mapping(root.get("vpn_profiles"), "vpn_profiles")
    apps = _mapping(root.get("applications", {}), "applications")
    if not profiles:
        raise ProfileError("at least one VPN profile is required")
    name_pattern = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
    output_profiles = {}
    for name, value in profiles.items():
        if not isinstance(name, str) or not name_pattern.fullmatch(name):
            raise ProfileError(f"invalid VPN profile name: {name!r}")
        profile = _mapping(value, f"profile {name}")
        _keys(profile, {"selection", "sharing"}, f"profile {name}")
        sharing = profile.get("sharing", "shared")
        if sharing not in ("shared", "isolated"):
            raise ProfileError(f"profile {name} sharing must be shared or isolated")
        selection = _mapping(profile.get("selection"), f"profile {name} selection")
        mode = selection.get("mode")
        if mode == "fastest":
            _keys(
                selection,
                {"mode", "filter", "minimum_improvement_ms", "minimum_improvement_percent"},
                f"profile {name} selection",
            )
            expression = selection.get("filter")
            if not isinstance(expression, str) or not expression.strip():
                raise ProfileError(f"profile {name} requires a filter")
            try:
                compile_filter(expression)
            except ValueError as exc:
                raise ProfileError(f"profile {name}: {exc}") from exc
            for field, limit in (("minimum_improvement_ms", None), ("minimum_improvement_percent", 100)):
                value = selection.get(field, 0)
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ProfileError(f"profile {name} {field} must be a non-negative number")
                import math

                if not math.isfinite(value) or value < 0 or (limit is not None and value > limit):
                    raise ProfileError(f"profile {name} {field} is outside its permitted range")
            normalised = dict(selection)
        elif mode == "country":
            _keys(selection, {"mode", "country"}, f"profile {name} selection")
            country = selection.get("country")
            if not isinstance(country, str) or not re.fullmatch(r"[a-zA-Z]{2}", country):
                raise ProfileError(f"profile {name} country must be a two-letter code")
            normalised = {"mode": mode, "country": normalise_country_code(country.lower())}
        elif mode == "pinned":
            _keys(selection, {"mode", "server"}, f"profile {name} selection")
            server = selection.get("server")
            canonical = normalise_server_identity(server) if isinstance(server, str) else None
            if canonical is None:
                raise ProfileError(f"profile {name} requires a valid NordVPN server identity")
            normalised = {"mode": mode, "server": canonical}
        else:
            raise ProfileError(f"profile {name} has unsupported selection mode: {mode!r}")
        output_profiles[name] = {"selection": normalised, "sharing": sharing}
    default_name = defaults.get("vpn")
    if not isinstance(default_name, str) or default_name not in output_profiles:
        raise ProfileError("defaults.vpn must name an existing profile")
    if output_profiles[default_name]["sharing"] != "shared":
        raise ProfileError("the default profile must be shared")
    output_apps = {}
    for name, value in apps.items():
        if not isinstance(name, str) or not name_pattern.fullmatch(name):
            raise ProfileError(f"invalid application name: {name!r}")
        app = _mapping(value, f"application {name}")
        _keys(app, {"executable", "vpn"}, f"application {name}")
        executable = app.get("executable")
        if not isinstance(executable, str) or not executable.startswith("/") or not executable.strip():
            raise ProfileError(f"application {name} executable must be an absolute path")
        vpn = app.get("vpn", default_name)
        if not isinstance(vpn, str) or vpn not in output_profiles:
            raise ProfileError(f"application {name} refers to an unknown VPN profile")
        output_apps[name] = {"executable": executable, "vpn": vpn}
    return {
        "version": 1,
        "defaults": {"vpn": default_name},
        "vpn_profiles": output_profiles,
        "applications": output_apps,
    }


def resolve_application(policy, name):
    """Return the assigned profile and whether the application inherits the default."""
    checked = validate_policy(policy)
    app = checked["applications"].get(name)
    return {"application": name, "vpn": app["vpn"] if app else checked["defaults"]["vpn"], "inherited": app is None}
