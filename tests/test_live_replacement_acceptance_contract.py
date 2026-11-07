"""Adversarial read-only checks in the production replacement acceptance runner."""

from pathlib import Path
from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_generation_handover import GenerationHandoverError
from tools.probe_live_tunnel_replacement import ProbeError, verify_adversarial_recovery


def report(disposition="draining_active_consumers", *, selected="generation-b", packet=True):
    return {
        "disposition": disposition,
        "selected_generation": selected,
        "selected_packet_verified": packet,
        "network_changes_applied": False,
        "automatic_kernel_repair_authorised": False,
    }


def evidence(config, **kwargs):
    if kwargs.get("expected_profile") or kwargs.get("expected_allocation_key"):
        raise GenerationHandoverError("wrong binding")
    if kwargs.get("packet_verifier") is not None:
        return report("selected_generation_drift_fail_closed", packet=False)
    return report()


def test_adversarial_acceptance_requires_repeatable_fail_closed_refusal():
    with patch("tools.probe_live_tunnel_replacement.recover_generation", side_effect=evidence) as recovery:
        verify_adversarial_recovery(
            {}, Path("handover"), Path("leases"), expected_disposition="draining_active_consumers"
        )
    assert recovery.call_count == 6
    assert sum(bool(call.kwargs.get("execute")) for call in recovery.call_args_list) == 3


@pytest.mark.parametrize(
    "broken",
    [
        lambda value: {**value, "network_changes_applied": True},
        lambda value: {**value, "automatic_kernel_repair_authorised": True},
        lambda value: {**value, "disposition": "eligible_for_explicit_retirement"},
    ],
)
def test_adversarial_acceptance_rejects_unexpected_read_only_result(broken):
    with (
        patch("tools.probe_live_tunnel_replacement.recover_generation", return_value=broken(report())),
        pytest.raises(ProbeError),
    ):
        verify_adversarial_recovery(
            {}, Path("handover"), Path("leases"), expected_disposition="draining_active_consumers"
        )


def test_adversarial_acceptance_refuses_cross_profile_success():
    with (
        patch("tools.probe_live_tunnel_replacement.recover_generation", return_value=report()),
        pytest.raises(ProbeError, match="cross-profile"),
    ):
        verify_adversarial_recovery(
            {}, Path("handover"), Path("leases"), expected_disposition="draining_active_consumers"
        )


def test_adversarial_acceptance_refuses_unhealthy_selected_generation_not_fail_closed():
    def unsafe(config, **kwargs):
        if kwargs.get("expected_profile") or kwargs.get("expected_allocation_key"):
            raise GenerationHandoverError("wrong binding")
        return report()

    with (
        patch("tools.probe_live_tunnel_replacement.recover_generation", side_effect=unsafe),
        pytest.raises(ProbeError, match="fail-closed"),
    ):
        verify_adversarial_recovery(
            {}, Path("handover"), Path("leases"), expected_disposition="draining_active_consumers"
        )


def test_adversarial_acceptance_rejects_post_refusal_selection_drift():
    baseline = report()
    changed = report(selected="generation-a")
    sequence = iter(
        [baseline, baseline, None, None, report("selected_generation_drift_fail_closed", packet=False), changed]
    )

    def changing(config, **kwargs):
        value = next(sequence)
        if value is None:
            raise GenerationHandoverError("wrong binding")
        return value

    with (
        patch("tools.probe_live_tunnel_replacement.recover_generation", side_effect=changing),
        pytest.raises(ProbeError, match="changed the selected generation"),
    ):
        verify_adversarial_recovery(
            {}, Path("handover"), Path("leases"), expected_disposition="draining_active_consumers"
        )
