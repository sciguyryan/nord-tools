"""Durable, conservative generation handover records.

A handover record is an administrative coordination journal, not kernel ownership
proof. Existing processes remain pinned to their original namespace; only new
launches can select a replacement after independent privileged verification.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from nord_tools_internal.nordvpn_consumer_reference_store import (
    ConsumerReferenceError,
    locked_consumer_references,
    read_private_json,
    write_private_json,
)


class GenerationHandoverError(ValueError):
    """Invalid or unsafe generation handover transition."""


_PRIVILEGED_TRANSITION = object()


@dataclass(frozen=True)
class AllocationGeneration:
    """Durable identity joining a logical allocation to its kernel scope."""

    profile: str
    allocation_key: str
    generation_id: str
    kernel_profile: str
    policy_sha256: str


def _generation(value: object, policy_sha256: str) -> dict:
    required = {"profile", "allocation_key", "generation_id", "kernel_profile", "policy_sha256"}
    if not isinstance(value, dict) or set(value) != required:
        raise GenerationHandoverError("invalid allocation generation")
    if not all(_name(value[key]) for key in ("profile", "allocation_key", "generation_id", "kernel_profile")):
        raise GenerationHandoverError("invalid allocation generation identity")
    if value["policy_sha256"] != policy_sha256:
        raise GenerationHandoverError("allocation generation policy mismatch")
    return dict(value)


def _name(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 256


def _validate(document: object) -> dict:
    if not isinstance(document, dict):
        raise GenerationHandoverError("invalid generation handover document")
    legacy_keys = {
        "version",
        "profile",
        "old",
        "replacement",
        "phase",
        "policy_sha256",
    }
    generation_keys = legacy_keys | {"generations"}
    if set(document) not in (legacy_keys, generation_keys):
        raise GenerationHandoverError("invalid generation handover document")
    if document["version"] not in (1, 2) or type(document["version"]) is not int:
        raise GenerationHandoverError("unsupported generation handover version")
    if not all(_name(document[key]) for key in ("profile", "old", "replacement")):
        raise GenerationHandoverError("invalid generation identity")
    if document["old"] == document["replacement"]:
        raise GenerationHandoverError("replacement generation must be distinct")
    if document["phase"] not in {"prepared", "verified", "active", "draining"}:
        raise GenerationHandoverError("unknown generation phase")
    digest = document["policy_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise GenerationHandoverError("invalid pinned policy fingerprint")
    result = dict(document)
    if document["version"] == 2:
        if set(document) != generation_keys or not isinstance(document["generations"], dict):
            raise GenerationHandoverError("generation handover lacks allocation bindings")
        if set(document["generations"]) != {document["old"], document["replacement"]}:
            raise GenerationHandoverError("generation bindings do not match handover identities")
        generations = {key: _generation(value, digest) for key, value in document["generations"].items()}
        if any(
            value["generation_id"] != key or value["profile"] != document["profile"]
            for key, value in generations.items()
        ):
            raise GenerationHandoverError("generation binding conflicts with handover identity")
        if generations[document["old"]]["kernel_profile"] == generations[document["replacement"]]["kernel_profile"]:
            raise GenerationHandoverError("replacement generation must own a distinct kernel profile")
        result["generations"] = generations
    elif set(document) != legacy_keys:
        raise GenerationHandoverError("legacy handover contains generation fields")
    return result


def policy_digest(policy: object) -> str:
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_handover(path: str | Path) -> dict:
    try:
        return _validate(read_private_json(path))
    except ConsumerReferenceError as exc:
        raise GenerationHandoverError(str(exc)) from exc


def prepare_handover(path: str | Path, *, profile: str, old: str, replacement: str, policy: object) -> dict:
    """Record intent without changing any application assignment or tunnel."""
    record = _validate(
        {
            "version": 1,
            "profile": profile,
            "old": old,
            "replacement": replacement,
            "phase": "prepared",
            "policy_sha256": policy_digest(policy),
        }
    )
    with locked_consumer_references(path):
        if Path(path).exists() or Path(path).is_symlink():
            raise GenerationHandoverError("handover already exists; reconcile it explicitly")
        write_private_json(path, record)
    return record


def prepare_generation_handover(
    path: str | Path,
    *,
    old: AllocationGeneration,
    replacement: AllocationGeneration,
    policy: object,
) -> dict:
    """Record a replacement whose generations are bound to real ownership scopes."""
    digest = policy_digest(policy)
    record = _validate(
        {
            "version": 2,
            "profile": old.profile,
            "old": old.generation_id,
            "replacement": replacement.generation_id,
            "phase": "prepared",
            "policy_sha256": digest,
            "generations": {
                old.generation_id: asdict(old),
                replacement.generation_id: asdict(replacement),
            },
        }
    )
    if old.profile != replacement.profile or old.policy_sha256 != digest or replacement.policy_sha256 != digest:
        raise GenerationHandoverError("generation profile or policy binding changed")
    with locked_consumer_references(path):
        if Path(path).exists() or Path(path).is_symlink():
            raise GenerationHandoverError("handover already exists; reconcile it explicitly")
        write_private_json(path, record)
    return record


def advance_handover(
    path: str | Path,
    *,
    expected_phase: str,
    next_phase: str,
    policy: object,
    verified: bool = False,
    old_consumers: int | None = None,
    _authority: object | None = None,
) -> dict:
    """Persist a monotonic transition; never treat this as privileged evidence.

    The caller must obtain fresh independent kernel and lease verification while
    holding the appropriate lifecycle authority before asserting `verified`.
    No transition here alters routing, kernel resources or application leases.
    """
    transitions = {"prepared": "verified", "verified": "active", "active": "draining"}
    if transitions.get(expected_phase) != next_phase:
        raise GenerationHandoverError("invalid or backwards handover transition")
    if type(verified) is not bool or not verified:
        raise GenerationHandoverError("fresh external verification required")
    if next_phase == "draining" and (type(old_consumers) is not int or old_consumers != 0):
        raise GenerationHandoverError("old generation still has consumers or no lease evidence")
    with locked_consumer_references(path):
        current = read_handover(path)
        if current["version"] == 2 and _authority is not _PRIVILEGED_TRANSITION:
            raise GenerationHandoverError("allocation-bound transitions require the privileged replacement executor")
        if current["phase"] != expected_phase or current["policy_sha256"] != policy_digest(policy):
            raise GenerationHandoverError("stale phase or policy changed during handover")
        updated = {**current, "phase": next_phase}
        write_private_json(path, updated)
    return updated


def _advance_verified_handover(path: str | Path, **arguments) -> dict:
    """Executor-only transition after fresh ownership and tunnel verification."""
    return advance_handover(path, **arguments, _authority=_PRIVILEGED_TRANSITION)


def selected_generation(document: object, *, policy: object) -> str:
    """Describe launch selection only; callers must still verify live authority."""
    record = _validate(document)
    if record["policy_sha256"] != policy_digest(policy):
        raise GenerationHandoverError("policy fingerprint changed")
    return record["replacement"] if record["phase"] in {"active", "draining"} else record["old"]


def selected_allocation(document: object, *, policy: object) -> AllocationGeneration:
    """Return the exact selected allocation; legacy journals are ambiguous."""
    record = _validate(document)
    if record["policy_sha256"] != policy_digest(policy):
        raise GenerationHandoverError("policy fingerprint changed")
    if record["version"] != 2:
        raise GenerationHandoverError("legacy handover has no allocation-generation binding")
    return AllocationGeneration(**record["generations"][selected_generation(record, policy=policy)])
