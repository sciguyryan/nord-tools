"""Conservative live application of persistent desired VPN state.

Only absent allocations are eligible for automatic creation. Existing resource
replacement, retirement, disputed evidence and recovery remain explicit
separately authorised operations; none is silently treated as convergence.
"""

from __future__ import annotations

import json

from nord_tools_internal.nordvpn_allocation_profiles import expand_allocation_profiles
from nord_tools_internal.nordvpn_discovery import discover
from nord_tools_internal.nordvpn_execution_lock import lifecycle_execution_lock
from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_live_update_policy import classify_live_updates
from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_restore_executor import restore_boot_state
from nord_tools_internal.nordvpn_startup import validate_startup_config
from nord_tools_internal.nordvpn_state_reconcile import derive_actual_state, reconcile_desired


def _read(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as source:
            return json.load(source)
    except (OSError, ValueError) as exc:
        raise RegistryError(f"cannot read live reconciliation evidence: {path}: {exc}") from exc


def _assess(config: dict, observe) -> dict:
    policy = validate_policy(_read(config["policy"]))
    desired, _ = expand_allocation_profiles(policy)
    journal = validate_journal(_read(config["journal"]))
    bindings = _read(config["bindings"])
    intents = _read(config["intent"])
    preflight = preflight_ownership(journal, bindings, observe(), intents)
    actual = derive_actual_state(journal, bindings, preflight)
    graph = _read(config["graph"]) if config["graph"] else None
    result = reconcile_desired(desired, actual, graph)
    decisions = result["decisions"]
    update_policy = classify_live_updates(policy, decisions)
    # A create-only pass must not proceed while any other profile is in an
    # ambiguous or non-converged state. This is a whole-operation refusal.
    allowed = {"converged", "create_pending"}
    unsafe = [d for d in decisions if d["action"] not in allowed]
    if preflight.get("operator_review_required") or result.get("unresolved_intents") or result.get("unclaimed"):
        unsafe.append({"profile": "<ownership>", "action": "review_required"})
    return {
        "schema_version": 1,
        "mode": "live_apply_assessment",
        "network_changes_applied": False,
        "eligible_for_create_only_apply": not unsafe,
        "decisions": decisions,
        "refusals": unsafe,
        "unclaimed": result.get("unclaimed", []),
        "unresolved_intents": result.get("unresolved_intents", []),
        "update_policy": update_policy,
    }


def apply_live_state(config: object, *, execute: bool = False, observe=None, restore=None) -> dict:
    """Reconcile live ownership, then create absent profiles only if safe.

    A dry run is strictly read-only. Execution delegates to the established
    restoration executor, which takes its own lifecycle lock, re-observes the
    kernel and revalidates creation-time bindings before any mutation. A prior
    assessment is never accepted as mutation authority.
    """
    validated = validate_startup_config(config)
    if not validated["intent"]:
        raise RegistryError("live apply requires a durable operation intent store")
    observer = observe or discover
    with lifecycle_execution_lock(validated["journal"]):
        assessment = _assess(validated, observer)
    if not execute:
        return assessment
    if not assessment["eligible_for_create_only_apply"]:
        raise RegistryError(
            "live apply refused: in-place updates are unsupported; use the reported replacement, retirement or review authority"
        )
    # An injected restoration executor is for deterministic offline testing.
    # The real executor rechecks every authority boundary under its own lock.
    executor = restore or restore_boot_state
    result = executor(validated)
    return {
        **assessment,
        "mode": "live_apply_result",
        "network_changes_applied": bool(result.get("network_changes_applied")),
        "restoration": result,
    }
