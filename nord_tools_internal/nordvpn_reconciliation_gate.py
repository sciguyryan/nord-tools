"""Offline Part 6 reconciliation gate for untrusted observation and ownership claims.

The output is a diagnostic decision, never authorisation to mutate the kernel.
"""

from __future__ import annotations

from nord_tools_internal.nordvpn_reconcile import plan_reconciliation


class ReconciliationGateError(ValueError):
    """A reconciliation gate input is inconsistent or unsupported."""


def assess_reconciliation(policy: dict, inventory: dict, evidence: object) -> dict:
    """Classify each planned change using exact, explicitly supplied evidence.

    Evidence is advisory even when it reports verified ownership: independent,
    privileged, creation-time proof must be checked again at execution time.
    """
    plan = plan_reconciliation(policy, inventory)
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"version", "profiles"}
        or type(evidence["version"]) is not int
        or evidence["version"] != 1
    ):
        raise ReconciliationGateError("evidence requires version 1 and profiles")
    records = evidence["profiles"]
    if not isinstance(records, dict):
        raise ReconciliationGateError("evidence.profiles must be an object")
    planned_names = {item["profile"] for item in plan["operations"]}
    if set(records) - planned_names:
        raise ReconciliationGateError("evidence contains an unknown profile")
    for name, item in records.items():
        if not isinstance(item, dict) or set(item) != {"ownership", "observation"}:
            raise ReconciliationGateError(f"invalid evidence for {name}")
        if item["ownership"] not in ("unverified", "conflicting", "independently_observed") or item[
            "observation"
        ] not in ("current", "stale", "missing"):
            raise ReconciliationGateError(f"invalid evidence state for {name}")
    decisions = []
    for operation in plan["operations"]:
        name = operation["profile"]
        action = operation["action"]
        proof = records.get(name)
        if action == "blocked":
            status, reason = "blocked", "external ownership conflict"
        elif action == "unchanged":
            status, reason = "observe_only", "no requested change"
        elif proof is None:
            status, reason = "blocked", "missing independent observation"
        elif proof["ownership"] != "independently_observed":
            status, reason = "blocked", "ownership not independently observed"
        elif proof["observation"] != "current":
            status, reason = "blocked", "observation is not current"
        else:
            status, reason = "requires_privileged_reverification", "offline evidence cannot authorise execution"
        decisions.append({"profile": name, "action": action, "status": status, "reason": reason})
    return {
        "schema_version": 1,
        "mode": "offline_reconciliation_gate",
        "network_changes_applied": False,
        "safe_to_execute": False,
        "blocked": any(item["status"] == "blocked" for item in decisions),
        "decisions": decisions,
    }
