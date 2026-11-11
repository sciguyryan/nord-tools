"""Conservative live apply must not turn observation into mutation authority."""

from contextlib import nullcontext
from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_live_apply import apply_live_state
from nord_tools_internal.nordvpn_registry import RegistryError


CONFIG = {
    "version": 1,
    "policy": "/tmp/policy.json",
    "journal": "/tmp/journal.json",
    "bindings": "/tmp/bindings.json",
    "run_record": "/tmp/runs.json",
    "intent": "/tmp/intents.json",
    "tunnels": {},
}


def assessment(action="create_pending", **overrides):
    result = {
        "schema_version": 1,
        "decisions": [{"profile": "alpha", "action": action}],
        "unresolved_intents": [],
        "unclaimed": [],
        "operator_review_required": False,
    }
    result.update(overrides)
    return result


@pytest.mark.parametrize("action", ["blocked", "retire_pending", "configuration_changed", "configuration_unverified"])
def test_unsafe_decisions_refuse_execution(action):
    called = []
    with (
        patch("nord_tools_internal.nordvpn_live_apply.lifecycle_execution_lock", return_value=nullcontext()),
        patch(
            "nord_tools_internal.nordvpn_live_apply._assess",
            return_value={
                "eligible_for_create_only_apply": False,
                "refusals": [{"action": action}],
            },
        ),
        pytest.raises(RegistryError, match="live apply refused"),
    ):
        apply_live_state(CONFIG, execute=True, restore=lambda _: called.append("restored"))
    assert not called


def test_dry_run_does_not_call_restoration():
    with (
        patch("nord_tools_internal.nordvpn_live_apply.lifecycle_execution_lock", return_value=nullcontext()),
        patch(
            "nord_tools_internal.nordvpn_live_apply._assess",
            return_value={
                "eligible_for_create_only_apply": True,
                "network_changes_applied": False,
            },
        ),
    ):
        result = apply_live_state(CONFIG, restore=lambda _: pytest.fail("dry run invoked restoration"))
    assert result["network_changes_applied"] is False


def test_create_only_delegates_to_revalidating_executor():
    calls = []
    with (
        patch("nord_tools_internal.nordvpn_live_apply.lifecycle_execution_lock", return_value=nullcontext()),
        patch(
            "nord_tools_internal.nordvpn_live_apply._assess",
            return_value={
                "eligible_for_create_only_apply": True,
                "network_changes_applied": False,
            },
        ),
    ):
        result = apply_live_state(
            CONFIG,
            execute=True,
            restore=lambda config: calls.append(config) or {"network_changes_applied": True, "restored": ["alpha"]},
        )
    assert len(calls) == 1
    assert result["network_changes_applied"] is True
    assert result["restoration"]["restored"] == ["alpha"]


def test_missing_intent_refused_before_observation():
    with pytest.raises(RegistryError, match="durable operation intent"):
        apply_live_state({**CONFIG, "intent": None}, observe=lambda: pytest.fail("unexpected observation"))


def test_fresh_assessment_includes_immutable_update_policy():
    from nord_tools_internal.nordvpn_live_apply import _assess

    decisions = assessment(action="configuration_changed")
    update = {"in_place_updates_supported": False, "updates": [{"strategy": "generation_replacement"}]}
    with (
        patch("nord_tools_internal.nordvpn_live_apply._read", side_effect=[{}, {}, {}, {}]),
        patch("nord_tools_internal.nordvpn_live_apply.validate_policy", return_value={"vpn_profiles": {}}) as policy,
        patch("nord_tools_internal.nordvpn_live_apply.expand_allocation_profiles", return_value=({}, {})),
        patch("nord_tools_internal.nordvpn_live_apply.validate_journal", return_value={}),
        patch("nord_tools_internal.nordvpn_live_apply.preflight_ownership", return_value={}),
        patch("nord_tools_internal.nordvpn_live_apply.derive_actual_state", return_value={}),
        patch("nord_tools_internal.nordvpn_live_apply.reconcile_desired", return_value=decisions),
        patch("nord_tools_internal.nordvpn_live_apply.classify_live_updates", return_value=update) as classify,
    ):
        result = _assess({**CONFIG, "graph": None}, lambda: {})
    policy.assert_called_once()
    classify.assert_called_once_with({"vpn_profiles": {}}, decisions["decisions"])
    assert result["update_policy"] == update
    assert result["eligible_for_create_only_apply"] is False


@pytest.mark.parametrize(
    "extra",
    [
        {"operator_review_required": True},
        {"unclaimed": [{"identifier": "foreign"}]},
        {"unresolved_intents": [{"operation": "pending"}]},
    ],
)
def test_ownership_uncertainty_refuses_create(extra):
    from nord_tools_internal.nordvpn_live_apply import _assess

    with (
        patch("nord_tools_internal.nordvpn_live_apply._read", side_effect=[{}, {}, {}, {}]),
        patch("nord_tools_internal.nordvpn_live_apply.validate_policy", return_value={}),
        patch("nord_tools_internal.nordvpn_live_apply.expand_allocation_profiles", return_value=({}, {})),
        patch("nord_tools_internal.nordvpn_live_apply.validate_journal", return_value={}),
        patch(
            "nord_tools_internal.nordvpn_live_apply.preflight_ownership",
            return_value={"operator_review_required": extra.get("operator_review_required", False)},
        ),
        patch("nord_tools_internal.nordvpn_live_apply.derive_actual_state", return_value={}),
        patch("nord_tools_internal.nordvpn_live_apply.classify_live_updates", return_value={}),
        patch("nord_tools_internal.nordvpn_live_apply.reconcile_desired", return_value=assessment(**extra)),
    ):
        result = _assess({**CONFIG, "graph": None}, lambda: {})
    assert result["eligible_for_create_only_apply"] is False
