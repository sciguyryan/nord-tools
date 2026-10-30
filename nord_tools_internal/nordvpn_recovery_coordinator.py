"""Offline transaction checkpoint and interruption-recovery assessment.

This module deliberately cannot execute, resume or authorise network mutations.
A checkpoint is diagnostic history, not independent creation-time ownership proof.
"""

from __future__ import annotations

from nord_tools_internal.nordvpn_transaction_plan import STAGES


class RecoveryContractError(ValueError):
    """A transaction checkpoint violates the offline recovery contract."""


def assess_checkpoint(operation: object, checkpoint: object) -> dict:
    """Validate an ordered stage prefix and conservatively classify recovery.

    A successful stage record is not evidence that the corresponding kernel
    action occurred. Even a complete record requires privileged revalidation.
    """
    if not isinstance(operation, dict) or set(operation) != {"profile", "action"}:
        raise RecoveryContractError("operation requires profile and action")
    profile, action = operation["profile"], operation["action"]
    if not isinstance(profile, str) or not profile or action not in STAGES:
        raise RecoveryContractError("unsupported transaction operation")
    if not isinstance(checkpoint, dict) or set(checkpoint) != {"version", "profile", "action", "completed", "outcome"}:
        raise RecoveryContractError("invalid checkpoint fields")
    if type(checkpoint["version"]) is not int or checkpoint["version"] != 1:
        raise RecoveryContractError("unsupported checkpoint version")
    if checkpoint["profile"] != profile or checkpoint["action"] != action:
        raise RecoveryContractError("checkpoint belongs to a different transaction")
    stages = STAGES[action]
    completed = checkpoint["completed"]
    if not isinstance(completed, list) or any(not isinstance(stage, str) for stage in completed):
        raise RecoveryContractError("completed stages must be an array of names")
    if completed != list(stages[: len(completed)]):
        raise RecoveryContractError("completed stages must be an ordered, unique prefix")
    outcome = checkpoint["outcome"]
    if outcome not in ("interrupted", "failed", "recorded_complete"):
        raise RecoveryContractError("unsupported checkpoint outcome")
    if outcome == "recorded_complete" and len(completed) != len(stages):
        raise RecoveryContractError("complete outcome requires every stage")
    if outcome != "recorded_complete" and len(completed) == len(stages):
        raise RecoveryContractError("interrupted or failed outcome cannot claim every stage complete")
    return {
        "schema_version": 1,
        "mode": "offline_recovery_assessment",
        "profile": profile,
        "action": action,
        "completed": list(completed),
        "next_unverified_stage": stages[len(completed)] if len(completed) < len(stages) else None,
        "outcome": outcome,
        "requires_fresh_privileged_observation": True,
        "requires_independent_ownership_proof": True,
        "safe_to_resume": False,
        "safe_to_rollback": False,
        "safe_to_delete": False,
        "network_changes_applied": False,
        "recovery_disposition": "inspect_actual_state_and_journal; preserve_existing_or_remain_fail_closed",
    }
