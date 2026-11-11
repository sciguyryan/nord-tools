"""Offline drift classification for untrusted desired and observed snapshots.

Never use this diagnostic to authorise kernel mutation or resource retirement.
"""

from __future__ import annotations

from collections.abc import Mapping


class DriftAssessmentError(ValueError):
    """The supplied snapshots are ambiguous or malformed."""


def _snapshot(value: object, name: str) -> dict[str, dict[str, str]]:
    if not isinstance(value, Mapping):
        raise DriftAssessmentError(f"{name} must be a mapping")
    result = {}
    for profile, record in value.items():
        if not isinstance(profile, str) or not profile.strip():
            raise DriftAssessmentError(f"{name} contains an invalid profile")
        if not isinstance(record, Mapping) or set(record) != {"allocation", "fingerprint"}:
            raise DriftAssessmentError(f"{name}.{profile} requires allocation and fingerprint")
        if any(not isinstance(item, str) or not item.strip() for item in record.values()):
            raise DriftAssessmentError(f"{name}.{profile} contains an invalid value")
        result[profile] = dict(record)
    return result


def assess_drift(desired: object, observed: object, ownership: object) -> dict:
    """Classify drift without trusting names, fingerprints or ownership assertions.

    Ownership is an untrusted caller-supplied status, not independently verified
    creation-time proof. Even matching observations cannot authorise mutation.
    """
    target = _snapshot(desired, "desired")
    actual = _snapshot(observed, "observed")
    if not isinstance(ownership, Mapping) or set(ownership) - set(actual):
        raise DriftAssessmentError("ownership must cover only observed profiles")
    if any(value not in ("unverified", "conflicting", "independently_observed") for value in ownership.values()):
        raise DriftAssessmentError("invalid ownership status")
    decisions = []
    for profile in sorted(set(target) | set(actual)):
        wanted = target.get(profile)
        found = actual.get(profile)
        if found is None:
            state, obligation = "missing", "inspect_before_create"
        elif wanted is None:
            state, obligation = "unexpected", "quarantine_and_inspect_no_retirement"
        elif wanted == found:
            state, obligation = "matching", "observe_only"
        elif wanted["allocation"] != found["allocation"]:
            state, obligation = "allocation_drift", "stage_immutable_replacement_after_verified_inspection"
        else:
            state, obligation = "configuration_drift", "plan_immutable_replacement_after_verified_inspection"
        proof = ownership.get(profile, "unverified")
        if found is not None and proof != "independently_observed":
            obligation = "block_and_investigate_ownership"
        decisions.append(
            {
                "profile": profile,
                "state": state,
                "ownership_claim": proof,
                "next_obligation": obligation,
                "requires_privileged_reverification": True,
                "safe_to_mutate": False,
                "safe_to_delete": False,
            }
        )
    return {
        "schema_version": 1,
        "mode": "offline_drift_assessment",
        "network_changes_applied": False,
        "safe_to_execute": False,
        "decisions": decisions,
    }
