"""Fail-closed recovery triage for interrupted managed-resource operations.

This module produces diagnostic recommendations only. Neither a journal nor an
interface fingerprint is independently verifiable proof of kernel ownership.
"""

from __future__ import annotations

from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_resource_fingerprint import compare_fingerprints


def assess_recovery(journal: object, recorded: object, observation: object) -> dict:
    """Correlate lifecycle and interface evidence without authorising actions.

    Missing fingerprint evidence is deliberately an error rather than a reason
    to assume that a resource is absent. All results require operator review.
    """
    validated = validate_journal(journal)
    fingerprints = compare_fingerprints(validated, recorded, observation)
    by_id = {item["allocation_id"]: item for item in fingerprints["resources"]}
    states = {event["allocation_id"]: event["state"] for event in validated["events"]}
    findings = []
    for allocation in validated["allocations"]["resources"]:
        token = allocation["allocation_id"]
        state = states.get(token, "unrecorded")
        evidence = by_id.get(token)
        if allocation["kind"] != "interface":
            classification = "unsupported_resource"
        elif evidence is None:
            classification = "insufficient_evidence"
        elif evidence["finding"] != "fingerprint_matches_unverified":
            classification = "identity_drift_or_missing"
        elif state in {"creating", "retiring", "failed", "degraded"}:
            classification = "interrupted_or_uncertain"
        elif state == "retired":
            classification = "possible_name_reuse"
        elif state == "active":
            classification = "active_claim_unverified"
        else:
            classification = "unprovisioned_claim_unverified"
        findings.append(
            {
                "allocation_id": token,
                "kind": allocation["kind"],
                "identifier": allocation["identifier"],
                "lifecycle_state": state,
                "fingerprint_finding": evidence["finding"] if evidence else None,
                "classification": classification,
                "operator_review_required": True,
            }
        )
    return {
        "mode": "read_only_recovery_triage",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_modify": False,
        "safe_to_delete": False,
        "automatic_recovery_permitted": False,
        "resources": findings,
    }
