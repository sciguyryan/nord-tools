"""Pure, non-executable management views for configured routes and cleanup."""

from __future__ import annotations

from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_reconcile import validate_inventory


def topology_graph(policy: dict, *, ascii_only: bool = False, scope: str = "persistent") -> str:
    """Render configuration intent, never a claim about live connections."""
    checked = validate_policy(policy)
    default = checked["defaults"]["vpn"]
    profiles = checked["vpn_profiles"]
    applications = checked["applications"]
    tee, last, vertical = ("+-- ", "`-- ", "|   ") if ascii_only else ("├── ", "└── ", "│   ")
    blank = "    "
    lines = [f"[root] (configured {scope} intent; NOT live networking)"]
    order = [default, *sorted(name for name in profiles if name != default)]
    for index, name in enumerate(order):
        profile = profiles[name]
        prefix = last if index == len(order) - 1 else tee
        children_prefix = blank if index == len(order) - 1 else vertical
        selection = profile["selection"]
        destination = selection.get("country", selection.get("server", selection.get("filter", "unknown")))
        lines.append(
            f"{prefix}[{name}: {profile['sharing']}] -> {selection['mode']}:{destination} -> Internet (planned)"
        )
        assigned = sorted(app for app, entry in applications.items() if entry["vpn"] == name)
        if name == default:
            assigned.append("other applications (inherited)")
        if not assigned:
            lines.append(f"{children_prefix}{last}(no assigned applications)")
        for position, app in enumerate(assigned):
            lines.append(f"{children_prefix}{last if position == len(assigned) - 1 else tee}{app}")
    return "\n".join(lines)


def cleanup_plan(inventory: dict) -> dict:
    """Describe candidate retirements; never authorise removal from claims alone.

    External resources are excluded, and even listed Nord Tools claims require
    fresh independent kernel ownership evidence before any future execution.
    """
    observed = validate_inventory(inventory)
    candidates = sorted(name for name, entry in observed.items() if entry["owner"] == "nord-tools")
    excluded = sorted(name for name, entry in observed.items() if entry["owner"] != "nord-tools")
    return {
        "schema_version": 1,
        "mode": "offline_cleanup_preview",
        "network_changes_applied": False,
        "safe_to_execute": False,
        "ownership_verified": False,
        "candidates": [
            {"profile": name, "action": "retire_if_independently_verified", "state": observed[name]["state"]}
            for name in candidates
        ],
        "excluded_external_profiles": excluded,
        "requirements": [
            "fresh independent resource ownership verification",
            "dependency-aware teardown",
            "durable recovery journal",
            "fail-closed traffic protection",
            "preserve unrelated host networking",
        ],
    }
