"""Adversarial offline replacement planning tests."""

import pytest

from nord_tools_internal.nordvpn_replacement_stage import ReplacementStageError, plan_staged_replacement


def plan(**changes):
    args = {
        "current": {"profile": "work", "allocation": "old"},
        "proposed": {"profile": "work", "allocation": "new"},
        "dependents": ["browser", "editor"],
        "verification": {"tunnel": True, "dns": True, "firewall": True},
    }
    args.update(changes)
    return plan_staged_replacement(**args)


def test_complete_report_never_grants_cutover_or_deletion():
    result = plan()
    assert result["reported_checks_complete"]
    assert not result["safe_to_cut_over"]
    assert not result["safe_to_retire_old"]
    assert not result["network_changes_applied"]
    assert result["existing_assignment_preserved"]
    assert result["preserved_dependents"] == ["browser", "editor"]


def test_missing_checks_preserve_current_assignment():
    result = plan(verification={"tunnel": True, "dns": False, "firewall": True})
    assert result["next_planning_obligation"] == "verify_staged_tunnel_dns_and_firewall"
    assert result["existing_assignment_preserved"]
    assert not result["safe_to_cut_over"]


@pytest.mark.parametrize(
    "changes",
    [
        {"current": {"profile": "work", "allocation": "same"}, "proposed": {"profile": "work", "allocation": "same"}},
        {"proposed": {"profile": "other", "allocation": "new"}},
        {"dependents": ["browser", "browser"]},
        {"dependents": ["browser", ""]},
        {"verification": {"tunnel": 1, "dns": True, "firewall": True}},
        {"verification": {"tunnel": True, "dns": True}},
        {"current": {"profile": "work", "allocation": "old", "owner": "claimed"}},
        {"proposed": {"profile": "work", "allocation": ""}},
    ],
)
def test_unsafe_or_ambiguous_plans_rejected(changes):
    with pytest.raises(ReplacementStageError):
        plan(**changes)


def test_input_is_not_modified_and_output_is_deterministic():
    dependents = ["editor", "browser"]
    first = plan(dependents=dependents)
    assert dependents == ["editor", "browser"]
    assert first == plan(dependents=["browser", "editor"])
