"""Live replacement readiness must not grant mutation authority."""

from contextlib import nullcontext
from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_replacement_readiness import assess_replacement_readiness
from nord_tools_internal.nordvpn_registry import RegistryError


CONFIG = {
    "version": 1,
    "policy": "/tmp/policy.json",
    "journal": "/tmp/journal.json",
    "bindings": "/tmp/bindings.json",
    "intent": "/tmp/intents.json",
    "run_record": "/tmp/runs.json",
    "tunnels": {},
}


@pytest.mark.parametrize(
    "action,active,expected",
    [
        ("converged", [], []),
        ("configuration_changed", [], ["profile_not_converged"]),
        ("converged", [{"profile": "alpha", "application": "browser"}], ["active_consumer_leases"]),
        (
            "retire_pending",
            [{"profile": "alpha", "application": "browser"}],
            ["profile_not_converged", "active_consumer_leases"],
        ),
    ],
)
def test_live_gate_remains_read_only(action, active, expected):
    with (
        patch("nord_tools_internal.nordvpn_replacement_readiness.lifecycle_execution_lock", return_value=nullcontext()),
        patch(
            "nord_tools_internal.nordvpn_replacement_readiness.locked_consumer_references", return_value=nullcontext()
        ),
        patch("nord_tools_internal.nordvpn_replacement_readiness._read", side_effect=[{}, {}, {}, {}]),
        patch("nord_tools_internal.nordvpn_replacement_readiness.validate_policy", return_value={}),
        patch(
            "nord_tools_internal.nordvpn_replacement_readiness.expand_allocation_profiles",
            return_value=({"vpn_profiles": {"alpha": {}}}, {}),
        ),
        patch("nord_tools_internal.nordvpn_replacement_readiness.validate_journal", return_value={}),
        patch("nord_tools_internal.nordvpn_replacement_readiness.preflight_ownership", return_value={}),
        patch("nord_tools_internal.nordvpn_replacement_readiness.derive_actual_state", return_value={}),
        patch(
            "nord_tools_internal.nordvpn_replacement_readiness.reconcile_desired",
            return_value={"decisions": [{"profile": "alpha", "action": action}]},
        ),
        patch("nord_tools_internal.nordvpn_replacement_readiness.read_leases", return_value={"leases": active}),
    ):
        result = assess_replacement_readiness(CONFIG, "alpha", "/tmp/leases.json", observe=lambda: {})
    assert result["blockers"] == expected
    assert result["eligible_for_non_disruptive_preparation"] is (not expected)
    assert result["safe_to_cut_over"] is False
    assert result["safe_to_retire_old"] is False
    assert result["network_changes_applied"] is False


def test_missing_intent_refuses_before_observation():
    with pytest.raises(RegistryError, match="durable intent"):
        assess_replacement_readiness({**CONFIG, "intent": None}, "alpha", "/tmp/leases.json")


@pytest.mark.parametrize("profile,lease", [("", "/tmp/leases.json"), ("alpha", "relative.json")])
def test_invalid_inputs_refuse_before_observation(profile, lease):
    with pytest.raises(RegistryError):
        assess_replacement_readiness(CONFIG, profile, lease)


def test_unrelated_nonconvergence_blocks_preparation():
    with (
        patch("nord_tools_internal.nordvpn_replacement_readiness.lifecycle_execution_lock", return_value=nullcontext()),
        patch(
            "nord_tools_internal.nordvpn_replacement_readiness.locked_consumer_references", return_value=nullcontext()
        ),
        patch("nord_tools_internal.nordvpn_replacement_readiness._read", side_effect=[{}, {}, {}, {}]),
        patch("nord_tools_internal.nordvpn_replacement_readiness.validate_policy", return_value={}),
        patch(
            "nord_tools_internal.nordvpn_replacement_readiness.expand_allocation_profiles",
            return_value=({"vpn_profiles": {"alpha": {}}}, {}),
        ),
        patch("nord_tools_internal.nordvpn_replacement_readiness.validate_journal", return_value={}),
        patch("nord_tools_internal.nordvpn_replacement_readiness.preflight_ownership", return_value={}),
        patch("nord_tools_internal.nordvpn_replacement_readiness.derive_actual_state", return_value={}),
        patch(
            "nord_tools_internal.nordvpn_replacement_readiness.reconcile_desired",
            return_value={
                "decisions": [{"profile": "alpha", "action": "converged"}, {"profile": "beta", "action": "blocked"}]
            },
        ),
        patch("nord_tools_internal.nordvpn_replacement_readiness.read_leases", return_value={"leases": []}),
    ):
        result = assess_replacement_readiness(CONFIG, "alpha", "/tmp/leases.json", observe=lambda: {})
    assert result["blockers"] == ["other_profiles_not_converged"]
