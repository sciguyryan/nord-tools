"""Diagnose stale allocation claims without treating names as ownership evidence."""

from __future__ import annotations

from nord_tools_internal.nordvpn_evidence import correlate
from nord_tools_internal.nordvpn_identity import validate_allocations


def inspect_identity_evidence(ledger: object, observation: object) -> dict:
    """Classify observed names, retaining allocation IDs without granting authority.

    Even a name match cannot verify an allocation ID: Linux names can be reused.
    A future provisioner must establish an independently readable binding.
    """
    allocations = validate_allocations(ledger)
    legacy = {
        "version": 1,
        "resources": [
            {key: item[key] for key in ("kind", "identifier", "profile", "owner")} for item in allocations["resources"]
        ],
    }
    evidence = correlate(legacy, observation)
    by_key = {(item["kind"], item["identifier"]): item for item in evidence["findings"]}
    findings = []
    for item in allocations["resources"]:
        status = by_key[(item["kind"], item["identifier"])]["evidence"]
        classification = {
            "name_observed": "unverified_name_match",
            "name_missing": "stale_or_unprovisioned",
            "ambiguous_or_unknown_scope": "unverifiable_scope",
            "unsupported_evidence_kind": "unsupported_evidence",
        }[status]
        findings.append({**item, "classification": classification, "allocation_binding_verified": False})
    return {
        "schema_version": 1,
        "mode": "read_only_allocation_evidence",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_modify": False,
        "safe_to_delete": False,
        "findings": findings,
    }
