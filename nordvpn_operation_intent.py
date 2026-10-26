"""Validated, non-authoritative operation intents for future privileged provisioning.

An intent records what an operator planned, not what happened in the kernel.
It cannot confer ownership or authorise resource mutation.
"""

from __future__ import annotations

import copy
import re
import secrets

from nordvpn_lifecycle import validate_journal
from nordvpn_registry import RegistryError

_OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_ACTIONS = {"create", "retire"}
_OUTCOMES = {"pending", "completed", "failed", "uncertain"}


def validate_intents(document: object, journal: object) -> dict:
    """Validate operation history and its allocation bindings, rejecting rewrites."""
    validated = validate_journal(journal)
    allocations = {item["allocation_id"]: item for item in validated["allocations"]["resources"]}
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "operations"}
        or type(document["version"]) is not int
        or document["version"] != 1
        or not isinstance(document["operations"], list)
    ):
        raise RegistryError("operation intents require version 1 and operations")
    ids = set()
    active = set()
    result = []
    for entry in document["operations"]:
        if not isinstance(entry, dict) or set(entry) != {
            "operation_id",
            "allocation_id",
            "action",
            "outcome",
            "journal_sequence",
        }:
            raise RegistryError("invalid operation intent fields")
        op_id, token = entry["operation_id"], entry["allocation_id"]
        if not isinstance(op_id, str) or not _OPERATION_ID.fullmatch(op_id) or op_id in ids or token not in allocations:
            raise RegistryError("invalid or reused operation identity")
        if (
            not isinstance(entry["action"], str)
            or entry["action"] not in _ACTIONS
            or not isinstance(entry["outcome"], str)
            or entry["outcome"] not in _OUTCOMES
        ):
            raise RegistryError("invalid operation action or outcome")
        sequence = entry["journal_sequence"]
        if type(sequence) is not int or not 1 <= sequence <= len(validated["events"]):
            raise RegistryError("operation references invalid journal sequence")
        event = validated["events"][sequence - 1]
        expected = "creating" if entry["action"] == "create" else "retiring"
        if event["allocation_id"] != token or event["state"] != expected:
            raise RegistryError("operation does not match journal transition")
        if token in active:
            raise RegistryError("multiple unresolved operations for allocation")
        if entry["outcome"] in {"pending", "uncertain"}:
            active.add(token)
        ids.add(op_id)
        result.append(copy.deepcopy(entry))
    return {"version": 1, "operations": result}


def begin_intent(document: object, journal: object, allocation_id: str, action: str) -> dict:
    """Record a unique pending intent against an existing lifecycle transition."""
    validated = validate_intents(document, journal)
    lifecycle = validate_journal(journal)
    if not isinstance(action, str) or action not in _ACTIONS:
        raise RegistryError("invalid operation action")
    expected = "creating" if action == "create" else "retiring"
    matching = [event for event in lifecycle["events"] if event["allocation_id"] == allocation_id]
    if not matching or matching[-1]["state"] != expected:
        raise RegistryError("operation requires matching current lifecycle state")
    if any(
        item["allocation_id"] == allocation_id and item["outcome"] in {"pending", "uncertain"}
        for item in validated["operations"]
    ):
        raise RegistryError("unresolved operation already exists")
    entry = {
        "operation_id": secrets.token_hex(16),
        "allocation_id": allocation_id,
        "action": action,
        "outcome": "pending",
        "journal_sequence": matching[-1]["sequence"],
    }
    return validate_intents({"version": 1, "operations": [*validated["operations"], entry]}, lifecycle)


def resolve_intent(document: object, journal: object, operation_id: str, outcome: str) -> dict:
    """Classify an intent; completion is still not evidence of kernel ownership."""
    validated = validate_intents(document, journal)
    if not isinstance(outcome, str) or outcome not in {"completed", "failed", "uncertain"}:
        raise RegistryError("invalid operation resolution")
    matching = [item for item in validated["operations"] if item["operation_id"] == operation_id]
    if len(matching) != 1 or matching[0]["outcome"] != "pending":
        raise RegistryError("operation is missing or already resolved")
    updated = copy.deepcopy(validated)
    for item in updated["operations"]:
        if item["operation_id"] == operation_id:
            item["outcome"] = outcome
    return validate_intents(updated, journal)


def inspect_intents(document: object, journal: object) -> dict:
    """Expose unresolved operations for manual recovery review."""
    validated = validate_intents(document, journal)
    return {
        "mode": "offline_operation_intents",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_modify": False,
        "safe_to_delete": False,
        "operator_review_required": True,
        "unresolved": [item for item in validated["operations"] if item["outcome"] in {"pending", "uncertain"}],
    }
