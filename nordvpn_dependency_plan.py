"""Deterministic, offline dependency ordering for simulated VPN reconciliation.

This is scheduling advice only, never authority to operate on host resources.
"""

from __future__ import annotations

from nordvpn_reconcile import ReconciliationError, plan_reconciliation, validate_inventory
from nordvpn_profiles import validate_policy


def plan_dependencies(policy: dict, inventory: dict, graph: object) -> dict:
    """Order creation from prerequisites outwards and retirement in reverse."""
    desired = validate_policy(policy)["vpn_profiles"]
    observed = validate_inventory(inventory)
    names = set(desired) | set(observed)
    if (
        not isinstance(graph, dict)
        or set(graph) != {"version", "dependencies"}
        or type(graph["version"]) is not int
        or graph["version"] != 1
        or not isinstance(graph["dependencies"], dict)
    ):
        raise ReconciliationError("dependency graph requires version 1 and dependencies object")
    if set(graph["dependencies"]) != names:
        raise ReconciliationError("dependency graph must enumerate every desired or observed profile")
    dependencies = {}
    for name, parents in graph["dependencies"].items():
        if (
            not isinstance(parents, list)
            or any(not isinstance(p, str) or p not in names or p == name for p in parents)
            or len(set(parents)) != len(parents)
        ):
            raise ReconciliationError(f"invalid dependencies for {name}")
        dependencies[name] = parents
    # A prerequisite cannot be retired while its dependent remains desired.
    for name in desired:
        if any(parent not in desired for parent in dependencies[name]):
            raise ReconciliationError(f"desired profile {name} depends on a retired profile")
    pending = {name: set(parents) for name, parents in dependencies.items()}
    ordered = []
    while pending:
        ready = sorted(name for name, parents in pending.items() if not parents)
        if not ready:
            raise ReconciliationError("dependency cycle detected")
        for name in ready:
            ordered.append(name)
            del pending[name]
        for parents in pending.values():
            parents.difference_update(ready)
    base = plan_reconciliation(policy, inventory)
    actions = {item["profile"]: item for item in base["operations"]}
    # External prerequisites must never be interpreted as safe to change.
    blocked = {name for name, item in actions.items() if item["action"] == "blocked"}
    operations = []
    for name in ordered:
        if name not in desired:
            continue
        parents_blocked = sorted(set(dependencies[name]) & blocked)
        if parents_blocked:
            blocked.add(name)
            operations.append(
                {"profile": name, "action": "blocked", "reason": "blocked prerequisites: " + ", ".join(parents_blocked)}
            )
        else:
            operations.append(actions[name])
    for name in reversed(ordered):
        if name not in desired and name in actions:
            operations.append(actions[name])
    return {
        "schema_version": 1,
        "mode": "offline_dependency_plan",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_execute": False,
        "blocked": bool(blocked),
        "operations": operations,
    }
