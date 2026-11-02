"""Read-only reconciliation of persistent desired state against observed resources.

Actual state is derived from a validated lifecycle journal, owner bindings and
a fresh ownership-verification preflight; it is never taken from resource names
or simulated claims. Every non-converged outcome is a plan for a separately
authorised privileged executor. This module performs no network changes.
"""

from __future__ import annotations

import json

from nord_tools_internal.nordvpn_ownership_verify import validate_bindings
from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_registry import RegistryError

# Non-converged outcomes that would need privileged execution to resolve.
PLAN_ACTIONS = frozenset({"create_pending", "retire_pending", "configuration_changed"})
_ENTRY_KEYS = frozenset(
    {
        "allocation_id",
        "kind",
        "identifier",
        "lifecycle_state",
        "finding",
        "verified",
        "recorded_identity",
        "observed_identity",
    }
)
_PREFLIGHT_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "network_changes_applied",
        "ownership_verified",
        "verified_resources",
        "unclaimed",
        "unresolved_intents",
        "resources",
    }
)


def validate_preflight(result: object, journal: object) -> dict[str, dict]:
    """Require a complete, current preflight report over exactly this journal."""
    if (
        not isinstance(result, dict)
        or not _PREFLIGHT_KEYS <= set(result)
        or result.get("mode") != "read_only_ownership_preflight"
        or type(result.get("schema_version")) is not int
        or result["schema_version"] != 1
        or result.get("network_changes_applied") is not False
        or not isinstance(result.get("resources"), list)
    ):
        raise RegistryError("requires a current read-only ownership preflight report")
    allocations = validate_journal(journal)["allocations"]["resources"]
    required = {item["allocation_id"] for item in allocations}
    findings: dict[str, dict] = {}
    for entry in result["resources"]:
        if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
            raise RegistryError("invalid preflight resource finding")
        if type(entry["verified"]) is not bool:
            raise RegistryError("invalid preflight verification flag")
        token = entry["allocation_id"]
        if token in findings:
            raise RegistryError(f"duplicate preflight finding for {token}")
        findings[token] = dict(entry)
    if set(findings) != required:
        raise RegistryError("preflight report does not cover every allocation exactly once")
    return findings


def derive_actual_state(journal: object, bindings: object, preflight_result: object) -> dict:
    """Group verified owned resources by profile into a deterministic actual state.

    A profile's configuration counts as recorded only when every binding of the
    profile agrees on an identical record; anything less is unverified evidence,
    which blocks convergence rather than suggesting a drift that was never seen.
    """
    validated = validate_journal(journal)
    validated_bindings = validate_bindings(bindings, validated)
    findings = validate_preflight(preflight_result, validated)
    allocations_by_token = {item["allocation_id"]: item for item in validated["allocations"]["resources"]}
    bindings_by_token = {entry["allocation_id"]: entry for entry in validated_bindings["bindings"]}
    lifecycle = {event["allocation_id"]: event["state"] for event in validated["events"]}
    profiles: dict[str, dict] = {}
    for allocation in sorted(
        allocations_by_token.values(), key=lambda item: (item["profile"], item["kind"], item["identifier"])
    ):
        profile = profiles.setdefault(
            allocation["profile"],
            {
                "present_resources": [],
                "absent_retired_resources": [],
                "blockers": [],
                "recorded_configuration": None,
                "configuration_recorded": False,
            },
        )
        finding = findings[allocation["allocation_id"]]
        resource = {
            "allocation_id": finding["allocation_id"],
            "kind": finding["kind"],
            "identifier": finding["identifier"],
        }
        if finding["finding"] == "verified_current":
            profile["present_resources"].append(resource)
        elif finding["verified"] and finding["finding"] == "consistent_retired":
            profile["absent_retired_resources"].append(resource)
        else:
            profile["blockers"].append(
                {
                    "allocation_id": finding["allocation_id"],
                    "kind": finding["kind"],
                    "identifier": finding["identifier"],
                    "finding": finding["finding"],
                }
            )
    for profile, record in sorted(profiles.items()):
        # Retired generations are history: their bindings record what was, not
        # what should converge now, so only allocations not recorded retired
        # participate in the configuration agreement.
        tokens = [
            token
            for token, item in allocations_by_token.items()
            if item["profile"] == profile and lifecycle.get(token) != "retired"
        ]
        configured = [bindings_by_token[token].get("configuration") for token in tokens if token in bindings_by_token]
        recorded_values = [value for value in configured if value is not None]
        if len(recorded_values) == len(tokens) and len({json.dumps(v, sort_keys=True) for v in recorded_values}) == 1:
            record["recorded_configuration"] = recorded_values[0]
            record["configuration_recorded"] = True
    return {
        "schema_version": 1,
        "mode": "derived_actual_state",
        "network_changes_applied": False,
        "ownership_claim_authority": False,
        "ownership_verified_all": bool(findings) and all(item["verified"] for item in findings.values()),
        "profiles": profiles,
        "unclaimed": preflight_result["unclaimed"],
        "unresolved_intents": preflight_result["unresolved_intents"],
    }


def _validate_graph(graph: object, desired: dict, names: set[str]) -> dict:
    """Validate a dependency graph over every desired and derived profile."""
    if (
        not isinstance(graph, dict)
        or set(graph) != {"version", "dependencies"}
        or type(graph["version"]) is not int
        or graph["version"] != 1
        or not isinstance(graph["dependencies"], dict)
    ):
        raise RegistryError("dependency graph requires version 1 and a dependencies object")
    if set(graph["dependencies"]) != names:
        raise RegistryError("dependency graph must enumerate every desired or derived profile")
    dependencies = {}
    for name, parents in graph["dependencies"].items():
        if (
            not isinstance(parents, list)
            or any(not isinstance(item, str) or item not in names or item == name for item in parents)
            or len(set(parents)) != len(parents)
        ):
            raise RegistryError(f"invalid dependencies for {name}")
        dependencies[name] = parents
    for name in desired:
        if any(parent not in desired for parent in dependencies[name]):
            raise RegistryError(f"desired profile {name} depends on a retired profile")
    pending = {name: set(parents) for name, parents in dependencies.items()}
    while pending:
        ready = sorted(name for name, parents in pending.items() if not parents)
        if not ready:
            raise RegistryError("dependency cycle detected")
        for name in ready:
            del pending[name]
        # A prerequisite cannot be retired while its dependent remains desired;
        # cycle rejection above keeps the propagation bounded as well.
        for parents in pending.values():
            parents.difference_update(ready)
    return dependencies


def reconcile_desired(policy: object, actual_state: object, graph: object | None = None) -> dict:
    """Classify how persistent desired state can converge, idempotently.

    Converged means every resource is ownership-verified and the recorded
    provisioned configuration matches the desired profile exactly. Everything
    else is a plan: blocked profiles are reported, not touched; creation
    requires additional provisioning that must never happen blindly, and
    retirement is reserved for the separately confirmed cleanup increment.
    """
    desired = validate_policy(policy)["vpn_profiles"]
    if (
        not isinstance(actual_state, dict)
        or actual_state.get("mode") != "derived_actual_state"
        or type(actual_state.get("schema_version")) is not int
        or actual_state["schema_version"] != 1
        or actual_state.get("network_changes_applied") is not False
        or not isinstance(actual_state.get("profiles"), dict)
    ):
        raise RegistryError("reconciliation requires derived actual state")
    observed = actual_state["profiles"]
    for name, record in observed.items():
        if (
            not isinstance(name, str)
            or not isinstance(record, dict)
            or not isinstance(record.get("present_resources"), list)
            or not isinstance(record.get("absent_retired_resources"), list)
            or not isinstance(record.get("blockers"), list)
            or type(record.get("configuration_recorded")) is not bool
        ):
            raise RegistryError("invalid derived actual-state profile record")
    names = set(desired) | set(observed)
    decisions = []
    for name in sorted(names):
        wanted = desired.get(name)
        record = observed.get(name)
        if wanted is not None and record is not None:
            if record["blockers"]:
                reasons = ", ".join(f"{b['identifier']}: {b['finding']}" for b in record["blockers"])
                action, reason = "blocked", f"unverified owned resources: {reasons}"
            elif not record["present_resources"] and record["absent_retired_resources"]:
                action, reason = "create_pending", "owned resources were retired; nothing is present"
            elif not record["configuration_recorded"]:
                action, reason = "configuration_unverified", "no recorded provisioned configuration"
            elif record["recorded_configuration"] != wanted:
                action, reason = "configuration_changed", "recorded configuration differs from desired intent"
            else:
                action, reason = "converged", "verified resources match desired configuration"
        elif wanted is not None:
            action, reason = "create_pending", "no owned resources exist; blind creation is prohibited"
        elif record is not None and record["blockers"]:
            reasons = ", ".join(f"{b['identifier']}: {b['finding']}" for b in record["blockers"])
            action, reason = "blocked", f"blocked resources are left alone: {reasons}"
        elif record is not None and record["present_resources"]:
            action, reason = "retire_pending", "no longer desired; verified resources remain"
        else:
            action, reason = "converged", "remaining allocations are consistently retired"
        decisions.append(
            {
                "profile": name,
                "action": action,
                "reason": reason,
                "verified_resources": sorted(record["present_resources"], key=lambda r: (r["kind"], r["identifier"]))
                if record is not None
                else [],
                "requires_privileged_execution": action in PLAN_ACTIONS,
            }
        )
    if graph is not None:
        dependencies = _validate_graph(graph, desired, names)
        # A blocked prerequisite blocks every desired dependent, matching the
        # offline dependency planner: converged evidence of resources cannot
        # compensate for a prerequisite that cannot safely be reconciled.
        blocked = {item["profile"] for item in decisions if item["action"] == "blocked"}
        changed = True
        while changed:
            changed = False
            for decision in decisions:
                profile = decision["profile"]
                if profile in desired and profile not in blocked:
                    parents_blocked = sorted(set(dependencies[profile]) & blocked)
                    if parents_blocked:
                        decision["action"] = "blocked"
                        decision["reason"] = "blocked prerequisite profiles: " + ", ".join(parents_blocked)
                        decision["verified_resources"] = []
                        blocked.add(profile)
                        changed = True
    for decision in decisions:
        decision["requires_privileged_execution"] = decision["action"] in PLAN_ACTIONS
    reconciled = all(item["action"] == "converged" for item in decisions)
    return {
        "schema_version": 1,
        "mode": "read_only_state_reconciliation",
        "network_changes_applied": False,
        "reconciled": reconciled,
        "safe_to_execute": False,
        "requires_privileged_execution": any(item["action"] in PLAN_ACTIONS for item in decisions),
        "transient_scope_excluded": True,
        "decisions": decisions,
        "unresolved_intents": actual_state.get("unresolved_intents", []),
        "limitations": (
            "Reconciles persistent desired state only; transient intent is never restored. "
            "Non-converged outcomes are plans: execution requires a separately authorised "
            "privileged executor that re-verifies ownership at the moment of mutation."
        ),
    }
