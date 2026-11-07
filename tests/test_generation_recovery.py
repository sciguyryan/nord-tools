"""Generation recovery refuses ambiguous and unsafe handover states."""

from contextlib import ExitStack, nullcontext
from unittest.mock import Mock, patch

import pytest

from nord_tools_internal.nordvpn_generation_handover import GenerationHandoverError, policy_digest
from nord_tools_internal.nordvpn_generation_recovery import _classify, recover_generation


RECORD = {
    "profile": "alpha",
    "old": "a",
    "replacement": "b",
    "phase": "prepared",
}


def observed(*, old=True, new=True):
    def state(healthy):
        return {
            "resource_count": 4 if healthy else 2,
            "states": ["active"] if healthy else ["creating"],
            "findings": ["verified_current"] if healthy else ["unobserved"],
        }

    return {"a": state(old), "b": state(new)}


def leases(*generation_ids):
    return {"version": 2, "leases": [{"profile": "alpha", "generation_id": x} for x in generation_ids]}


@pytest.mark.parametrize(
    ("phase", "old", "new", "consumers", "expected"),
    [
        ("prepared", True, False, (), "operator_review_partial_replacement"),
        ("prepared", True, True, (), "verify_replacement_before_promotion"),
        ("verified", True, True, (), "verified_awaiting_explicit_activation"),
        ("active", True, False, (), "selected_generation_drift_fail_closed"),
        ("active", True, True, ("a",), "draining_active_consumers"),
        ("active", True, True, (), "eligible_for_explicit_retirement"),
        ("draining", False, True, (), "operator_review_partial_retirement"),
        ("prepared", False, True, (), "operator_review_old_generation"),
    ],
)
def test_conservative_recovery_dispositions(phase, old, new, consumers, expected):
    record = {**RECORD, "phase": phase}
    result = _classify(record, observed(old=old, new=new), leases(*consumers))
    assert result["disposition"] == expected
    assert result["automatic_kernel_repair_authorised"] is False
    assert result["network_changes_applied"] is False


def test_other_profile_lease_cannot_hold_this_generation():
    other = leases()
    other["leases"].append({"profile": "beta", "generation_id": "a"})
    result = _classify({**RECORD, "phase": "active"}, observed(), other)
    assert result["disposition"] == "eligible_for_explicit_retirement"


def test_legacy_lease_refused():
    with pytest.raises(GenerationHandoverError, match="legacy"):
        _classify(RECORD, observed(), {"version": 1, "leases": []})


def test_absent_prepared_replacement_is_explicit_reprovision_candidate():
    state = observed()
    state["b"] = {"resource_count": 0, "states": [], "findings": []}
    result = _classify(RECORD, state, leases())
    assert result["disposition"] == "eligible_for_explicit_reprovision"
    assert not result["automatic_kernel_repair_authorised"]


def test_missing_selected_generation_is_not_reprovisioned_automatically():
    state = observed()
    state["b"] = {"resource_count": 0, "states": [], "findings": []}
    result = _classify({**RECORD, "phase": "active"}, state, leases())
    assert result["disposition"] == "selected_generation_drift_fail_closed"


def test_lease_against_absent_old_generation_requires_review():
    state = observed()
    state["a"] = {"resource_count": 0, "states": [], "findings": []}
    result = _classify({**RECORD, "phase": "draining"}, state, leases("a"))
    assert result["disposition"] == "operator_review_lease_without_generation"


def test_lease_allocation_mismatch_is_refused():
    record = {
        **RECORD,
        "generations": {
            "a": {"allocation_key": "profile:alpha", "kernel_profile": "alpha"},
            "b": {"allocation_key": "profile:alpha", "kernel_profile": "ntgen_b"},
        },
    }
    snapshot = leases("a")
    snapshot["leases"][0].update(allocation_key="profile:alpha", kernel_profile="ntgen_b")
    with pytest.raises(GenerationHandoverError, match="ownership binding"):
        _classify(record, observed(), snapshot)


def test_retired_old_generation_with_no_leases_is_converged():
    state = observed()
    state["a"] = {"resource_count": 4, "states": ["retired"], "findings": ["consistent_retired"]}
    result = _classify({**RECORD, "phase": "draining"}, state, leases())
    assert result["disposition"] == "old_generation_retired"


def test_retired_old_generation_with_lease_is_disputed():
    state = observed()
    state["a"] = {"resource_count": 4, "states": ["retired"], "findings": ["consistent_retired"]}
    result = _classify({**RECORD, "phase": "draining"}, state, leases("a"))
    assert result["disposition"] == "operator_review_lease_without_generation"


RECOVERY_POLICY = {
    "version": 1,
    "defaults": {"vpn": "alpha"},
    "vpn_profiles": {"alpha": {"selection": {"mode": "country", "country": "GB"}, "sharing": "shared"}},
    "applications": {},
}
RECOVERY_CONFIG = {
    "journal": "/state/journal.json",
    "bindings": "/state/bindings.json",
    "intent": "/state/intents.json",
    "policy": "/state/policy.json",
    "tunnels": {"alpha": {"dns_servers": ["10.0.0.1"]}},
}


def recovery_record(phase):
    digest = policy_digest(RECOVERY_POLICY)
    return {
        **RECORD,
        "version": 2,
        "phase": phase,
        "policy_sha256": digest,
        "generations": {
            "a": {
                "profile": "alpha",
                "allocation_key": "profile:alpha",
                "generation_id": "a",
                "kernel_profile": "alpha",
                "policy_sha256": digest,
            },
            "b": {
                "profile": "alpha",
                "allocation_key": "profile:alpha",
                "generation_id": "b",
                "kernel_profile": "ntgen_b",
                "policy_sha256": digest,
            },
        },
    }


def recovery_evidence(*, b_resources=4):
    resources = []
    findings = []
    events = []
    for profile, count in (("alpha", 4), ("ntgen_b", b_resources)):
        for index in range(count):
            allocation_id = f"{profile}-{index}"
            resources.append(
                {
                    "profile": profile,
                    "allocation_id": allocation_id,
                    "kind": "namespace" if index == 0 else "interface",
                }
            )
            findings.append({"allocation_id": allocation_id, "finding": "verified_current"})
            events.append({"allocation_id": allocation_id, "state": "active"})
    return {"allocations": {"resources": resources}, "events": events}, {"resources": findings, "unclaimed": []}


def recovery_patches(phase, *, b_resources=4):
    journal, preflight = recovery_evidence(b_resources=b_resources)
    return (
        patch("nord_tools_internal.nordvpn_generation_recovery.validate_startup_config", return_value=RECOVERY_CONFIG),
        patch("nord_tools_internal.nordvpn_generation_recovery.validate_policy", return_value=RECOVERY_POLICY),
        patch("nord_tools_internal.nordvpn_generation_recovery._read", return_value=RECOVERY_POLICY),
        patch("nord_tools_internal.nordvpn_generation_recovery.read_handover", return_value=recovery_record(phase)),
        patch("nord_tools_internal.nordvpn_generation_recovery.lifecycle_execution_lock", return_value=nullcontext()),
        patch("nord_tools_internal.nordvpn_generation_recovery.locked_consumer_references", return_value=nullcontext()),
        patch("nord_tools_internal.nordvpn_lifecycle.validate_journal", return_value=journal),
        patch("nord_tools_internal.nordvpn_ownership_verify.preflight_ownership", return_value=preflight),
        patch("nord_tools_internal.nordvpn_generation_recovery.read_runtime_consumers_locked", return_value=leases()),
        patch("nord_tools_internal.nordvpn_generation_recovery._verify_live_confinement"),
    )


def test_prepared_verified_generation_can_recover_durable_phase_without_kernel_changes():
    patches = recovery_patches("prepared")
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        with (
            patch("nord_tools_internal.nordvpn_generation_recovery._verify", return_value="nt-ns"),
            patch(
                "nord_tools_internal.nordvpn_generation_recovery._advance_verified_handover",
                return_value={"phase": "verified"},
            ) as advance,
        ):
            result = recover_generation(
                RECOVERY_CONFIG,
                handover_path="/state/handover",
                runtime_consumers_path="/state/leases",
                observe=lambda: {},
                execute=True,
                packet_verifier=lambda _: True,
            )
    assert result["phase"] == "verified"
    assert result["network_changes_applied"] is False
    advance.assert_called_once()


def test_read_only_recovery_never_invokes_privileged_transition():
    patches = recovery_patches("prepared")
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        with (
            patch("nord_tools_internal.nordvpn_generation_recovery._verify") as verify,
            patch("nord_tools_internal.nordvpn_generation_recovery._advance_verified_handover") as advance,
        ):
            result = recover_generation(
                RECOVERY_CONFIG,
                handover_path="/state/handover",
                runtime_consumers_path="/state/leases",
                observe=lambda: {},
                execute=False,
            )
    assert result["disposition"] == "verify_replacement_before_promotion"
    verify.assert_not_called()
    advance.assert_not_called()


def test_reprovision_requires_explicit_flag_and_production_reverification():
    patches = recovery_patches("prepared", b_resources=0)
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        provision = stack.enter_context(patch("nord_tools_internal.nordvpn_replacement_executor.prepare_replacement"))
        result = recover_generation(
            RECOVERY_CONFIG,
            handover_path="/state/handover",
            runtime_consumers_path="/state/leases",
            observe=lambda: {},
            execute=True,
        )
    assert result["disposition"] == "eligible_for_explicit_reprovision"
    provision.assert_not_called()


def test_explicit_reprovision_uses_production_executor():
    patches = recovery_patches("prepared", b_resources=0)
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        with (
            patch(
                "nord_tools_internal.nordvpn_replacement_executor.prepare_replacement",
                return_value={"phase": "verified", "network_changes_applied": True},
            ) as provision,
        ):
            result = recover_generation(
                RECOVERY_CONFIG,
                handover_path="/state/handover",
                runtime_consumers_path="/state/leases",
                observe=lambda: {},
                execute=True,
                allow_reprovision=True,
            )
    assert result["repair"] == "verified_reprovision"
    assert result["network_changes_applied"] is True
    provision.assert_called_once()


def test_active_selected_generation_is_never_reprovisioned_without_a_new_gate():
    patches = recovery_patches("active", b_resources=0)
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        provision = stack.enter_context(patch("nord_tools_internal.nordvpn_replacement_executor.prepare_replacement"))
        result = recover_generation(
            RECOVERY_CONFIG,
            handover_path="/state/handover",
            runtime_consumers_path="/state/leases",
            observe=lambda: {},
            execute=True,
            allow_reprovision=True,
        )
    assert result["disposition"] == "selected_generation_drift_fail_closed"
    provision.assert_not_called()


def test_active_selected_packet_failure_is_reported_as_fail_closed_drift():
    patches = recovery_patches("active")
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        stack.enter_context(
            patch("nord_tools_internal.nordvpn_generation_recovery._verify", side_effect=ValueError("no route"))
        )
        result = recover_generation(
            RECOVERY_CONFIG,
            handover_path="/state/handover",
            runtime_consumers_path="/state/leases",
            observe=lambda: {},
            execute=True,
            allow_reprovision=True,
        )
    assert result["disposition"] == "selected_generation_drift_fail_closed"
    assert result["selected_packet_verified"] is False
    assert result["network_changes_applied"] is False


def test_active_selected_packet_health_is_reported_separately_from_ownership():
    patches = recovery_patches("active")
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        verify = stack.enter_context(
            patch("nord_tools_internal.nordvpn_generation_recovery._verify", return_value="nt-ns")
        )
        result = recover_generation(
            RECOVERY_CONFIG,
            handover_path="/state/handover",
            runtime_consumers_path="/state/leases",
            observe=lambda: {},
            execute=False,
        )
    assert result["selected_packet_verified"] is True
    assert result["disposition"] == "eligible_for_explicit_retirement"
    verify.assert_called_once()


def test_manage_recovery_dispatches_pinned_handover_without_mutating_on_preview(capsys):
    import json
    import nordvpn_manage

    config = {**RECOVERY_CONFIG, "handovers": {"profile:alpha": "/state/handover"}}
    with (
        patch("nordvpn_manage.read_json", return_value=config),
        patch("nordvpn_manage.validate_startup_config", return_value=config),
        patch(
            "nord_tools_internal.nordvpn_generation_recovery.recover_generation",
            return_value={"mode": "generation_recovery"},
        ) as recover,
    ):
        status = nordvpn_manage.main(
            [
                "recover-generation",
                "--config",
                "/state/startup.json",
                "--profile",
                "alpha",
                "--runtime-consumers",
                "/state/leases",
            ]
        )
    assert status == 0
    assert json.loads(capsys.readouterr().out)["scope"] == "persistent"
    assert recover.call_args.kwargs["execute"] is False
    assert recover.call_args.kwargs["allow_reprovision"] is False


def test_manage_recovery_requires_execution_for_reprovision(capsys):
    import nordvpn_manage

    config = {**RECOVERY_CONFIG, "handovers": {"profile:alpha": "/state/handover"}}
    with (
        patch("nordvpn_manage.read_json", return_value=config),
        patch("nordvpn_manage.validate_startup_config", return_value=config),
        patch("nord_tools_internal.nordvpn_generation_recovery.recover_generation") as recover,
    ):
        status = nordvpn_manage.main(
            [
                "recover-generation",
                "--config",
                "/state/startup.json",
                "--profile",
                "alpha",
                "--runtime-consumers",
                "/state/leases",
                "--reprovision-absent",
            ]
        )
    assert status == 2
    recover.assert_not_called()


@pytest.mark.parametrize("phase", ["prepared", "verified", "active", "draining"])
def test_recovery_refuses_unresolved_ownership_before_any_repair(phase):
    patches = recovery_patches(phase)
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        stack.enter_context(
            patch(
                "nord_tools_internal.nordvpn_ownership_verify.preflight_ownership",
                return_value={"operator_review_required": True, "resources": []},
            )
        )
        provision = stack.enter_context(patch("nord_tools_internal.nordvpn_replacement_executor.prepare_replacement"))
        with pytest.raises(GenerationHandoverError, match="operator review"):
            recover_generation(
                RECOVERY_CONFIG,
                handover_path="/state/handover",
                runtime_consumers_path="/state/leases",
                observe=lambda: {},
                execute=True,
                allow_reprovision=True,
            )
    provision.assert_not_called()


@pytest.mark.parametrize("phase", ["prepared", "verified", "active", "draining"])
def test_recovery_refuses_policy_change_before_observation(phase):
    patches = recovery_patches(phase)
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        stack.enter_context(
            patch(
                "nord_tools_internal.nordvpn_generation_recovery.read_handover",
                return_value={**recovery_record(phase), "policy_sha256": "0" * 64},
            )
        )
        observe = Mock()
        with pytest.raises(GenerationHandoverError, match="current policy"):
            recover_generation(
                RECOVERY_CONFIG,
                handover_path="/state/handover",
                runtime_consumers_path="/state/leases",
                observe=observe,
                execute=True,
                allow_reprovision=True,
            )
    observe.assert_not_called()


@pytest.mark.parametrize(
    ("expected_profile", "expected_allocation_key", "error"),
    [("beta", None, "another profile"), (None, "profile:beta", "another allocation")],
)
def test_recovery_rejects_cross_profile_or_allocation_handover_before_observation(
    expected_profile, expected_allocation_key, error
):
    patches = recovery_patches("prepared")
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        observe = Mock()
        with pytest.raises(GenerationHandoverError, match=error):
            recover_generation(
                RECOVERY_CONFIG,
                handover_path="/state/handover",
                runtime_consumers_path="/state/leases",
                observe=observe,
                execute=True,
                allow_reprovision=True,
                expected_profile=expected_profile,
                expected_allocation_key=expected_allocation_key,
            )
    observe.assert_not_called()


def test_failed_verification_does_not_advance_prepared_record():
    patches = recovery_patches("prepared")
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        stack.enter_context(
            patch("nord_tools_internal.nordvpn_generation_recovery._verify", side_effect=ValueError("drift"))
        )
        advance = stack.enter_context(
            patch("nord_tools_internal.nordvpn_generation_recovery._advance_verified_handover")
        )
        with pytest.raises(ValueError, match="drift"):
            recover_generation(
                RECOVERY_CONFIG,
                handover_path="/state/handover",
                runtime_consumers_path="/state/leases",
                observe=lambda: {},
                execute=True,
            )
    advance.assert_not_called()


def test_verified_recovery_does_not_repeat_prepared_transition():
    patches = recovery_patches("verified")
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        advance = stack.enter_context(
            patch("nord_tools_internal.nordvpn_generation_recovery._advance_verified_handover")
        )
        result = recover_generation(
            RECOVERY_CONFIG,
            handover_path="/state/handover",
            runtime_consumers_path="/state/leases",
            observe=lambda: {},
            execute=True,
        )
    assert result["disposition"] == "verified_awaiting_explicit_activation"
    assert result["durable_record_changed"] is False
    advance.assert_not_called()


def test_live_confinement_rechecks_routes_peer_and_resolver():
    from nord_tools_internal.nordvpn_generation_recovery import _verify_live_confinement

    resources = [
        {"kind": "interface", "identifier": "ntwg123"},
        {"kind": "interface", "identifier": "ntul123"},
        {"kind": "interface", "identifier": "nthl123"},
    ]
    tunnel = {"endpoint_address": "198.51.100.1", "endpoint_port": 51820, "dns_servers": ["10.0.0.1"]}
    with (
        patch("nord_tools_internal.nordvpn_generation_recovery._verify_base_chains") as firewall,
        patch("nord_tools_internal.nordvpn_generation_recovery.verify_tunnel_route_readback") as route,
        patch("nord_tools_internal.nordvpn_generation_recovery.verify_dns_routes") as dns_routes,
        patch("nord_tools_internal.nordvpn_generation_recovery.verify_dns_peer_allowed_ips") as allowed,
        patch("nord_tools_internal.nordvpn_generation_recovery.verify_resolver_file") as resolver,
    ):
        _verify_live_confinement("nt-12345678", resources, tunnel)
    firewall.assert_called_once()
    route.assert_called_once_with("nt-12345678", "ntwg123", "ntul123", "198.51.100.1")
    dns_routes.assert_called_once()
    allowed.assert_called_once()
    resolver.assert_called_once()


def test_live_confinement_refuses_ambiguous_interface_roles():
    from nord_tools_internal.nordvpn_generation_recovery import _verify_live_confinement

    resources = [
        {"kind": "interface", "identifier": "ntwg123"},
        {"kind": "interface", "identifier": "ntwg456"},
        {"kind": "interface", "identifier": "ntul123"},
    ]
    with pytest.raises(GenerationHandoverError, match="ambiguous"):
        _verify_live_confinement("nt-12345678", resources, {"endpoint_address": "198.51.100.1"})


def test_active_firewall_drift_is_reported_without_repair_or_fallback():
    patches = recovery_patches("active")
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        stack.enter_context(patch("nord_tools_internal.nordvpn_generation_recovery._verify", return_value="nt-ns"))
        stack.enter_context(
            patch(
                "nord_tools_internal.nordvpn_generation_recovery._verify_live_confinement",
                side_effect=RuntimeError("nftables rules changed"),
            )
        )
        provision = stack.enter_context(patch("nord_tools_internal.nordvpn_replacement_executor.prepare_replacement"))
        result = recover_generation(
            RECOVERY_CONFIG,
            handover_path="/state/handover",
            runtime_consumers_path="/state/leases",
            observe=lambda: {},
            execute=True,
            allow_reprovision=True,
        )
    assert result["disposition"] == "selected_generation_drift_fail_closed"
    assert result["selected_packet_verified"] is False
    assert result["network_changes_applied"] is False
    provision.assert_not_called()


def test_retirement_requires_exact_consistent_retired_evidence():
    """An absent-looking but unverified finding cannot prove exact retirement."""
    state = observed()
    for finding in ("absent", "unobserved", "possible_name_reuse", "uncertain_intent"):
        state["a"] = {"resource_count": 4, "states": ["retired"], "findings": [finding]}
        result = _classify({**RECORD, "phase": "draining"}, state, leases())
        assert result["disposition"] == "operator_review_partial_retirement"
