"""Live updates route to explicit lifecycle authorities, never in-place mutation."""

import pytest

from nord_tools_internal.nordvpn_allocation_profiles import kernel_profile_for_allocation
from nord_tools_internal.nordvpn_live_update_policy import classify_live_updates
from nord_tools_internal.nordvpn_registry import RegistryError


POLICY = {
    "version": 1,
    "defaults": {"vpn": "primary"},
    "vpn_profiles": {
        "primary": {"selection": {"mode": "pinned", "server": "gb123"}},
        "isolated": {"selection": {"mode": "country", "country": "gb"}, "sharing": "isolated"},
    },
    "applications": {"browser": {"executable": "/usr/bin/browser", "vpn": "isolated"}},
}


def test_changed_shared_and_isolated_allocations_route_to_generation_replacement():
    isolated = kernel_profile_for_allocation("application:browser:profile:isolated", "isolated", "isolated")
    report = classify_live_updates(
        POLICY,
        [
            {"profile": "primary", "action": "configuration_changed"},
            {"profile": isolated, "action": "configuration_changed"},
        ],
    )
    assert report["in_place_updates_supported"] is False
    assert report["automatic_provider_reselection_supported"] is False
    assert report["startup_configuration_changes_require_explicit_replacement"] is True
    assert report["network_changes_applied"] is False
    updates = {entry["profile"]: entry for entry in report["updates"]}
    assert updates["primary"]["replacement_inputs"] == {
        "profile": "primary",
        "allocation_key": "profile:primary",
        "operator_must_choose": ["old_generation", "replacement_generation", "runtime_consumers"],
    }
    assert updates[isolated]["replacement_inputs"]["allocation_key"] == "application:browser:profile:isolated"
    assert all(not entry["in_place_mutation_authorised"] for entry in updates.values())


def test_each_non_update_outcome_names_only_its_existing_authority():
    actions = ["converged", "create_pending", "retire_pending", "configuration_unverified", "blocked"]
    decisions = [{"profile": f"observed_{index}", "action": action} for index, action in enumerate(actions)]
    report = classify_live_updates(POLICY, decisions)
    assert [entry["strategy"] for entry in report["updates"]] == [
        "none",
        "create_absent",
        "verified_retirement",
        "operator_review",
        "operator_review",
    ]


@pytest.mark.parametrize(
    "decisions",
    [None, [{"profile": "primary", "action": "unknown"}], [{"profile": "primary", "action": "converged"}] * 2],
)
def test_invalid_or_duplicate_reconciliation_decisions_are_refused(decisions):
    with pytest.raises(RegistryError):
        classify_live_updates(POLICY, decisions)
