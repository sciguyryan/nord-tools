"""Adversarial offline drift assessment tests."""

import pytest

from nord_tools_internal.nordvpn_drift_assessment import DriftAssessmentError, assess_drift


@pytest.mark.parametrize(
    ("desired", "observed", "ownership", "state", "obligation"),
    [
        ({"a": {"allocation": "n1", "fingerprint": "f1"}}, {}, {}, "missing", "inspect_before_create"),
        (
            {},
            {"a": {"allocation": "n1", "fingerprint": "f1"}},
            {"a": "independently_observed"},
            "unexpected",
            "quarantine_and_inspect_no_retirement",
        ),
        (
            {"a": {"allocation": "n1", "fingerprint": "f1"}},
            {"a": {"allocation": "n1", "fingerprint": "f1"}},
            {"a": "independently_observed"},
            "matching",
            "observe_only",
        ),
        (
            {"a": {"allocation": "n1", "fingerprint": "f1"}},
            {"a": {"allocation": "n2", "fingerprint": "f1"}},
            {"a": "independently_observed"},
            "allocation_drift",
            "stage_replacement_after_privileged_inspection",
        ),
        (
            {"a": {"allocation": "n1", "fingerprint": "f1"}},
            {"a": {"allocation": "n1", "fingerprint": "f2"}},
            {"a": "independently_observed"},
            "configuration_drift",
            "inspect_and_plan_repair",
        ),
        (
            {"a": {"allocation": "n1", "fingerprint": "f1"}},
            {"a": {"allocation": "n1", "fingerprint": "f2"}},
            {"a": "conflicting"},
            "configuration_drift",
            "block_and_investigate_ownership",
        ),
    ],
)
def test_classification(desired, observed, ownership, state, obligation):
    result = assess_drift(desired, observed, ownership)
    assert result["decisions"][0]["state"] == state
    assert result["decisions"][0]["next_obligation"] == obligation
    assert result["safe_to_execute"] is False
    assert result["network_changes_applied"] is False
    assert result["decisions"][0]["safe_to_delete"] is False


@pytest.mark.parametrize(
    ("desired", "observed", "ownership"),
    [
        ([], {}, {}),
        ({"": {"allocation": "a", "fingerprint": "f"}}, {}, {}),
        ({"a": {"allocation": "a"}}, {}, {}),
        ({"a": {"allocation": "a", "fingerprint": ""}}, {}, {}),
        ({}, {}, {"unknown": "unverified"}),
        ({}, {"a": {"allocation": "a", "fingerprint": "f"}}, {"a": "trusted"}),
    ],
)
def test_rejects_ambiguous_inputs(desired, observed, ownership):
    with pytest.raises(DriftAssessmentError):
        assess_drift(desired, observed, ownership)


def test_stable_sorted_output_and_no_input_mutation():
    desired = {key: {"allocation": key, "fingerprint": key} for key in ("z", "a")}
    result = assess_drift(desired, {}, {})
    assert [item["profile"] for item in result["decisions"]] == ["a", "z"]
    assert list(desired) == ["z", "a"]
