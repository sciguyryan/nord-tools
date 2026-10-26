"""Pure, offline reconciliation of desired VPN profiles and an observed inventory.

Inventory is an explicitly supplied simulation, never a trusted discovery of
kernel resources. No operation in this module modifies host networking.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from nordvpn_profiles import validate_policy


class ReconciliationError(ValueError):
    """An inventory is ambiguous or cannot safely be reconciled."""


def validate_inventory(document: object) -> dict:
    """Validate the versioned inventory, rejecting unknown ownership and shape."""
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "profiles"}
        or type(document["version"]) is not int
        or document["version"] != 1
    ):
        raise ReconciliationError("inventory requires version 1 and profiles")
    profiles = document["profiles"]
    if not isinstance(profiles, dict):
        raise ReconciliationError("inventory.profiles must be an object")
    validated = {}
    for name, record in profiles.items():
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name)
            or not isinstance(record, dict)
            or set(record) != {"owner", "configuration", "state"}
        ):
            raise ReconciliationError(f"invalid inventory record: {name!r}")
        if (
            not isinstance(record["owner"], str)
            or record["owner"] not in ("nord-tools", "external")
            or not isinstance(record["state"], str)
            or record["state"] not in ("ready", "missing", "degraded")
        ):
            raise ReconciliationError(f"invalid owner or state for {name}")
        configuration = record["configuration"]
        if not isinstance(configuration, dict) or set(configuration) != {"selection", "sharing"}:
            raise ReconciliationError(f"invalid configuration for {name}")
        # Use the same normalisation and strict field checks as desired intent.
        try:
            checked = validate_policy(
                {
                    "version": 1,
                    "defaults": {"vpn": name},
                    "vpn_profiles": {name: {**configuration, "sharing": "shared"}},
                    "applications": {},
                }
            )
        except (ValueError, TypeError) as exc:
            raise ReconciliationError(f"invalid profile {name}: {exc}") from exc
        if not isinstance(configuration["sharing"], str) or configuration["sharing"] not in ("shared", "isolated"):
            raise ReconciliationError(f"invalid sharing for {name}")
        validated[name] = {
            "owner": record["owner"],
            "state": record["state"],
            "configuration": {**checked["vpn_profiles"][name], "sharing": configuration["sharing"]},
        }
    return validated


def plan_reconciliation(policy: dict, inventory: dict) -> dict:
    """Calculate deterministic changes without trusting inventory as deletion authority.

    Even an inventory declaring Nord Tools ownership is only a planning input.
    Future execution must independently verify kernel ownership and safety.
    """
    desired = validate_policy(policy)["vpn_profiles"]
    observed = validate_inventory(inventory)
    operations = []
    for name in sorted(set(desired) | set(observed)):
        current = observed.get(name)
        target = desired.get(name)
        if current and current["owner"] != "nord-tools":
            if target is not None:
                operations.append({"profile": name, "action": "blocked", "reason": "external ownership conflict"})
            continue
        if target is None:
            operations.append({"profile": name, "action": "retire", "reason": "no longer desired"})
        elif current is None:
            operations.append({"profile": name, "action": "create"})
        elif current["state"] != "ready":
            operations.append({"profile": name, "action": "repair", "reason": current["state"]})
        elif current["configuration"] != target:
            operations.append({"profile": name, "action": "replace", "reason": "configuration changed"})
        else:
            operations.append({"profile": name, "action": "unchanged"})
    return {
        "schema_version": 1,
        "mode": "simulation_only",
        "network_changes_applied": False,
        "blocked": any(item["action"] == "blocked" for item in operations),
        "operations": operations,
    }


def load_inventory(path: str | Path) -> dict:
    """Read an explicit fixture; never discover or claim real host state."""
    path = Path(path)
    if path.is_symlink():
        raise ReconciliationError("refusing symlinked inventory")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReconciliationError(f"cannot read inventory: {exc}") from exc
