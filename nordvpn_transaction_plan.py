"""Offline transaction and interruption-recovery contract for VPN profile plans.

These steps describe safety obligations, not executable host operations.
"""

from __future__ import annotations

from nordvpn_dependency_plan import plan_dependencies


STAGES = {
    "create": (
        "verify_ownership_and_underlay",
        "prepare_isolated_resources",
        "install_fail_closed_protection",
        "verify_tunnel_and_dns",
        "activate_assignment",
    ),
    "repair": (
        "verify_ownership_and_underlay",
        "prepare_isolated_resources",
        "install_fail_closed_protection",
        "verify_tunnel_and_dns",
        "activate_assignment",
    ),
    "replace": (
        "verify_ownership_and_underlay",
        "prepare_replacement_without_disrupting_current",
        "install_fail_closed_protection",
        "verify_replacement_tunnel_and_dns",
        "switch_assignment_atomically",
        "retire_verified_old_resources",
    ),
    "retire": (
        "verify_ownership_and_dependents",
        "block_new_traffic",
        "detach_assignment",
        "remove_verified_owned_resources",
    ),
}


def plan_transactions(policy: dict, inventory: dict, graph: object) -> dict:
    """Describe gated stages and recovery obligations, without execution authority."""
    dependency = plan_dependencies(policy, inventory, graph)
    operations = []
    for operation in dependency["operations"]:
        action = operation["action"]
        entry = {"profile": operation["profile"], "action": action}
        if action in STAGES:
            entry["stages"] = list(STAGES[action])
            entry["interruption_policy"] = "keep_existing_connection_or_block_traffic; require_verified_recovery"
            entry["rollback_policy"] = "restore_verified_previous_assignment_or_remain_fail_closed"
            entry["requires"] = [
                "independent_resource_ownership",
                "live_network_preflight",
                "durable_operation_journal",
                "verified_firewall_and_dns_isolation",
            ]
        else:
            entry["stages"] = []
            if action == "blocked":
                entry["reason"] = operation["reason"]
        operations.append(entry)
    return {
        "schema_version": 1,
        "mode": "offline_transaction_contract",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_execute": False,
        "blocked": dependency["blocked"],
        "operations": operations,
        "recovery_rules": [
            "never infer ownership from a resource name or saved ledger alone",
            "never expose traffic outside the assigned tunnel during preparation or rollback",
            "never delete resources without fresh independent ownership verification",
            "after interruption, inspect actual state and the durable journal before resuming",
            "preserve unrelated tunnels and host networking",
        ],
    }
