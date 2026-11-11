"""Disputed drift is quarantined; only existing evidence-bound recovery remains."""

import pytest

from nord_tools_internal.nordvpn_drift_recovery_policy import classify_drift_recovery
from nord_tools_internal.nordvpn_registry import RegistryError


def item(token, profile, disposition, finding):
    return {
        "allocation_id": token,
        "profile": profile,
        "disposition": disposition,
        "finding": finding,
    }


def test_policy_separates_record_only_identity_bound_and_quarantined_profiles():
    report = classify_drift_recovery(
        [
            item("a", "absent", "complete_retirement_records", "resource_missing"),
            item("b", "owned", "resume_retirement", "verified_current"),
            item("c", "disputed", "review_required", "identity_mismatch"),
        ]
    )
    assert report["automatic_repair_authorised"] is False
    assert report["quarantined_profiles"] == ["disputed"]
    assert report["recoverable_profiles"] == ["absent", "owned"]
    profiles = {entry["profile"]: entry for entry in report["profiles"]}
    assert profiles["absent"]["status"] == "record_only_recovery"
    assert profiles["absent"]["kernel_mutation_possible"] is False
    assert profiles["owned"]["status"] == "identity_bound_recovery"
    assert profiles["owned"]["kernel_mutation_possible"] is True
    assert profiles["disputed"]["authority"] == "operator investigation only"


def test_any_review_item_quarantines_the_reported_profile():
    report = classify_drift_recovery(
        [
            item("a", "mixed", "complete_creation", "verified_current"),
            item("b", "mixed", "review_required", "binding_missing"),
        ]
    )
    assert report["quarantined_profiles"] == ["mixed"]
    assert report["recoverable_profiles"] == []


@pytest.mark.parametrize(
    "items",
    [
        None,
        [{}],
        [item("a", "p", "unknown", "x")],
        [item("a", "p", "review_required", "x")] * 2,
        [{**item("a", "p", "review_required", "x"), "profile_quarantined": "false"}],
    ],
)
def test_invalid_or_duplicate_recovery_items_are_refused(items):
    with pytest.raises(RegistryError):
        classify_drift_recovery(items)
