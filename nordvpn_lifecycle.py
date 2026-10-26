"""Conservative offline lifecycle journal for future managed network resources.

The journal is an auditable record, not independent kernel ownership evidence.
It cannot authorise changes to live networking, even for an active record.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile

from nordvpn_identity import validate_allocations
from nordvpn_registry import RegistryError

STATES = frozenset({"reserved", "creating", "active", "degraded", "retiring", "retired", "failed"})
TRANSITIONS = {
    "reserved": frozenset({"creating", "failed"}),
    "creating": frozenset({"active", "failed"}),
    "active": frozenset({"degraded", "retiring"}),
    "degraded": frozenset({"active", "retiring", "failed"}),
    "retiring": frozenset({"retired", "failed"}),
    "failed": frozenset({"creating", "retiring"}),
    "retired": frozenset(),
}


def _digest(entry: dict) -> str:
    """Bind journal events to an immutable allocation identity and resource tuple."""
    data = {key: entry[key] for key in ("kind", "identifier", "profile", "owner", "allocation_id")}
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_journal(document: object) -> dict:
    """Validate a complete, append-only-in-sequence lifecycle history."""
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "allocations", "events"}
        or type(document["version"]) is not int
        or document["version"] != 1
    ):
        raise RegistryError("lifecycle journal requires version 1, allocations and events")
    allocations = validate_allocations(document["allocations"])
    if not isinstance(document["events"], list):
        raise RegistryError("lifecycle events must be an array")
    identities = {item["allocation_id"]: item for item in allocations["resources"]}
    state = {}
    events = []
    for number, event in enumerate(document["events"], 1):
        if not isinstance(event, dict) or set(event) != {"sequence", "allocation_id", "state", "resource_digest"}:
            raise RegistryError("invalid lifecycle event fields")
        token = event["allocation_id"]
        if type(event["sequence"]) is not int or event["sequence"] != number or token not in identities:
            raise RegistryError("invalid lifecycle sequence or allocation identity")
        if event["resource_digest"] != _digest(identities[token]):
            raise RegistryError("lifecycle resource identity changed")
        next_state = event["state"]
        if not isinstance(next_state, str) or next_state not in STATES:
            raise RegistryError("invalid lifecycle state")
        previous = state.get(token)
        if (
            previous is None
            and next_state != "reserved"
            or previous is not None
            and next_state not in TRANSITIONS[previous]
        ):
            raise RegistryError(f"invalid lifecycle transition: {previous} -> {next_state}")
        state[token] = next_state
        events.append(dict(event))
    return {"version": 1, "allocations": allocations, "events": events}


def record_transition(document: object, allocation_id: str, state: str) -> dict:
    """Return a new validated journal; do not mutate the caller's document."""
    validated = validate_journal(document)
    allocations = {item["allocation_id"]: item for item in validated["allocations"]["resources"]}
    if allocation_id not in allocations:
        raise RegistryError("unknown allocation identity")
    event = {
        "sequence": len(validated["events"]) + 1,
        "allocation_id": allocation_id,
        "state": state,
        "resource_digest": _digest(allocations[allocation_id]),
    }
    return validate_journal({**validated, "events": [*validated["events"], event]})


def inspect_lifecycle(document: object, observed: object | None = None) -> dict:
    """Report unverified state and conflicts without granting ownership authority.

    Observations are explicit test fixtures, never trusted as kernel evidence.
    """
    validated = validate_journal(document)
    if observed is not None and (
        not isinstance(observed, list)
        or any(not isinstance(item, dict) or set(item) != {"kind", "identifier", "allocation_id"} for item in observed)
    ):
        raise RegistryError("invalid simulated observations")
    observations = (
        {} if observed is None else {(item["kind"], item["identifier"]): item["allocation_id"] for item in observed}
    )
    states = {event["allocation_id"]: event["state"] for event in validated["events"]}
    findings = []
    for resource in validated["allocations"]["resources"]:
        key = (resource["kind"], resource["identifier"])
        seen = observations.get(key)
        finding = (
            "unverified"
            if observed is None
            else "missing"
            if seen is None
            else "identity_conflict"
            if seen != resource["allocation_id"]
            else "claimed_not_verified"
        )
        findings.append(
            {
                "allocation_id": resource["allocation_id"],
                "kind": key[0],
                "identifier": key[1],
                "lifecycle_state": states.get(resource["allocation_id"], "unrecorded"),
                "finding": finding,
            }
        )
    return {
        "mode": "offline_lifecycle",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_modify": False,
        "safe_to_delete": False,
        "resources": findings,
    }


def write_journal(path: str | Path, document: object) -> None:
    """Atomically persist a validated journal, refusing symlink targets.

    This is an offline fixture writer. Multi-process locking and a privileged
    ownership registrar must precede any operational use.
    """
    target = Path(path)
    validated = validate_journal(document)
    if target.is_symlink() or target.parent.is_symlink():
        raise RegistryError("refusing symlinked journal path")
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".lifecycle-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(validated, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
