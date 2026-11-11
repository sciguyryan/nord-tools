"""Operator-facing quarantine policy for fresh recovery classifications."""

from __future__ import annotations

from nord_tools_internal.nordvpn_registry import RegistryError


_RECORD_ONLY = {"complete_creation", "resolve_create_failed", "complete_retirement_records"}
_IDENTITY_BOUND = {"rollback_creation", "resume_retirement"}
_REVIEW = "review_required"


def classify_drift_recovery(items: object) -> dict:
    """Group recovery evidence without granting authority beyond its executor."""
    if not isinstance(items, list):
        raise RegistryError("drift recovery policy requires recovery items")
    grouped: dict[str, list[dict]] = {}
    seen = set()
    for item in items:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("profile"), str)
            or not item["profile"]
            or not isinstance(item.get("allocation_id"), str)
            or not item["allocation_id"]
            or item["allocation_id"] in seen
            or item.get("disposition") not in _RECORD_ONLY | _IDENTITY_BOUND | {_REVIEW}
            or ("profile_quarantined" in item and type(item["profile_quarantined"]) is not bool)
        ):
            raise RegistryError("drift recovery policy received an invalid or duplicate recovery item")
        seen.add(item["allocation_id"])
        grouped.setdefault(item["profile"], []).append(item)
    profiles = []
    for profile, evidence in sorted(grouped.items()):
        dispositions = {item["disposition"] for item in evidence}
        quarantined = any(item.get("profile_quarantined", item["disposition"] == _REVIEW) for item in evidence)
        if quarantined:
            status = "quarantined"
            authority = "operator investigation only"
            kernel_mutation_possible = False
        elif dispositions & _IDENTITY_BOUND:
            status = "identity_bound_recovery"
            authority = "explicit operator recovery"
            kernel_mutation_possible = True
        else:
            status = "record_only_recovery"
            authority = "recovery bookkeeping"
            kernel_mutation_possible = False
        profiles.append(
            {
                "profile": profile,
                "status": status,
                "authority": authority,
                "kernel_mutation_possible": kernel_mutation_possible,
                "automatic_repair_authorised": False,
                "allocation_ids": sorted(item["allocation_id"] for item in evidence),
                "findings": sorted({str(item.get("finding", "unreported")) for item in evidence}),
            }
        )
    return {
        "schema_version": 1,
        "mode": "disputed_drift_recovery_policy",
        "network_changes_applied": False,
        "automatic_repair_authorised": False,
        "quarantined_profiles": [item["profile"] for item in profiles if item["status"] == "quarantined"],
        "recoverable_profiles": [item["profile"] for item in profiles if item["status"] != "quarantined"],
        "profiles": profiles,
        "limitations": (
            "Only the recovery executor may act on these classifications. Names, configuration matches and this "
            "report are never ownership proof; disputed profiles remain untouched."
        ),
    }
