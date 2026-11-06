"""Generation replacement integrates durable intent, verification and leases."""

from contextlib import nullcontext
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError
from nord_tools_internal.nordvpn_generation_handover import (
    AllocationGeneration,
    _advance_verified_handover,
    policy_digest,
    prepare_generation_handover,
    read_handover,
)
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_replacement_executor import (
    _production_provision,
    activate_replacement,
    prepare_replacement,
    retire_old_generation,
)
from nord_tools_internal.nordvpn_restore_executor import _apply_generation_selections


POLICY = {
    "version": 1,
    "defaults": {"vpn": "alpha"},
    "vpn_profiles": {"alpha": {"selection": {"mode": "country", "country": "GB"}, "sharing": "shared"}},
    "applications": {},
}
CONFIG = {
    "version": 1,
    "policy": "/state/policy.json",
    "journal": "/state/journal.json",
    "bindings": "/state/bindings.json",
    "intent": "/state/intents.json",
    "run_record": "/state/runs.json",
    "graph": None,
    "tunnels": {"alpha": {"dns_servers": ["10.0.0.1"]}},
    "credentials": {"alpha": "/state/key"},
}


def authority_patches():
    return (
        patch("nord_tools_internal.nordvpn_replacement_executor.validate_startup_config", return_value=CONFIG),
        patch("nord_tools_internal.nordvpn_replacement_executor.validate_policy", return_value=POLICY),
        patch("nord_tools_internal.nordvpn_replacement_executor.lifecycle_execution_lock", return_value=nullcontext()),
        patch(
            "nord_tools_internal.nordvpn_replacement_executor.locked_consumer_references", return_value=nullcontext()
        ),
    )


def test_failed_b_provisioning_leaves_a_selected_and_prepared_intent(tmp_path):
    handover = tmp_path / "handover.json"
    patches = authority_patches()
    with (
        patches[0],
        patches[1],
        patches[2],
        patches[3],
        patch("nord_tools_internal.nordvpn_replacement_executor._read", return_value={}),
        patch("nord_tools_internal.nordvpn_replacement_executor.validate_journal", return_value={}),
        patch("nord_tools_internal.nordvpn_replacement_executor.preflight_ownership", return_value={}),
        patch("nord_tools_internal.nordvpn_replacement_executor._generation_resources", return_value=[]),
        pytest.raises(RuntimeError, match="injected provisioning failure"),
    ):
        prepare_replacement(
            CONFIG,
            profile="alpha",
            allocation_key="profile:alpha",
            old_generation_id="generation-a",
            replacement_generation_id="generation-b",
            handover_path=str(handover),
            runtime_consumers_path=str(tmp_path / "leases.json"),
            observe=lambda: {},
            provision=lambda *_: (_ for _ in ()).throw(RuntimeError("injected provisioning failure")),
        )
    record = read_handover(handover)
    assert record["phase"] == "prepared"
    assert record["old"] == "generation-a"


def test_activation_failure_does_not_change_selection(tmp_path):
    handover = tmp_path / "handover.json"
    digest = policy_digest(POLICY)
    prepare_generation_handover(
        handover,
        old=AllocationGeneration("alpha", "profile:alpha", "generation-a", "alpha", digest),
        replacement=AllocationGeneration("alpha", "profile:alpha", "generation-b", "ntgen_b", digest),
        policy=POLICY,
    )
    _advance_verified_handover(handover, expected_phase="prepared", next_phase="verified", policy=POLICY, verified=True)
    patches = authority_patches()
    with (
        patches[0],
        patches[1],
        patches[2],
        patches[3],
        patch("nord_tools_internal.nordvpn_replacement_executor._read", return_value=POLICY),
        patch("nord_tools_internal.nordvpn_replacement_executor._verify", side_effect=RegistryError("unhealthy")),
        pytest.raises(RegistryError, match="unhealthy"),
    ):
        activate_replacement(
            CONFIG,
            handover_path=str(handover),
            runtime_consumers_path=str(tmp_path / "leases.json"),
            observe=lambda: {},
            packet_verifier=lambda _: False,
        )
    assert read_handover(handover)["phase"] == "verified"


def test_old_generation_lease_blocks_cleanup(tmp_path):
    handover = tmp_path / "handover.json"
    digest = policy_digest(POLICY)
    prepare_generation_handover(
        handover,
        old=AllocationGeneration("alpha", "profile:alpha", "generation-a", "alpha", digest),
        replacement=AllocationGeneration("alpha", "profile:alpha", "generation-b", "ntgen_b", digest),
        policy=POLICY,
    )
    _advance_verified_handover(handover, expected_phase="prepared", next_phase="verified", policy=POLICY, verified=True)
    _advance_verified_handover(handover, expected_phase="verified", next_phase="active", policy=POLICY, verified=True)
    cleanup = Mock()
    patches = authority_patches()
    with (
        patches[0],
        patches[1],
        patches[2],
        patches[3],
        patch("nord_tools_internal.nordvpn_replacement_executor._read", return_value=POLICY),
        patch(
            "nord_tools_internal.nordvpn_replacement_executor.read_runtime_consumers_locked",
            return_value={
                "version": 2,
                "leases": [{"generation_id": "generation-a"}],
            },
        ),
        pytest.raises(ConsumerReferenceError, match="retains consumers"),
    ):
        retire_old_generation(
            CONFIG,
            handover_path=str(handover),
            runtime_consumers_path=str(tmp_path / "leases.json"),
            observe=lambda: {},
            cleanup=cleanup,
            execute=True,
        )
    cleanup.assert_not_called()


def test_production_provision_projects_b_without_mutating_a_policy_file(tmp_path):
    journal = tmp_path / "journal.json"
    credential = tmp_path / "key"
    config = {
        **CONFIG,
        "journal": str(journal),
        "credentials": {"alpha": str(credential)},
        "tunnels": {"alpha": {"dns_servers": ["10.0.0.1"]}},
    }
    digest = policy_digest(POLICY)
    replacement = AllocationGeneration("alpha", "profile:alpha", "generation-b", "ntgen_b", digest)
    captured = {}

    def restore(generated):
        captured.update(generated)
        captured["policy_document"] = json.loads(Path(generated["policy"]).read_text(encoding="utf-8"))
        return {"network_changes_applied": True}

    with patch("nord_tools_internal.nordvpn_replacement_executor.restore_boot_state", side_effect=restore):
        _production_provision(config, POLICY, replacement)
    assert "alpha" not in captured["tunnels"]
    assert "ntgen_b" in captured["tunnels"]
    assert "alpha" not in captured["policy_document"]["vpn_profiles"]
    assert "ntgen_b" in captured["policy_document"]["vpn_profiles"]


def test_boot_projection_restores_active_selected_generation(tmp_path):
    handover = tmp_path / "handover.json"
    digest = policy_digest(POLICY)
    prepare_generation_handover(
        handover,
        old=AllocationGeneration("alpha", "profile:alpha", "generation-a", "alpha", digest),
        replacement=AllocationGeneration("alpha", "profile:alpha", "generation-b", "ntgen_b", digest),
        policy=POLICY,
    )
    _advance_verified_handover(handover, expected_phase="prepared", next_phase="verified", policy=POLICY, verified=True)
    _advance_verified_handover(handover, expected_phase="verified", next_phase="active", policy=POLICY, verified=True)
    projected, providers = _apply_generation_selections({"handovers": {"profile:alpha": str(handover)}}, POLICY)
    assert "alpha" not in projected["vpn_profiles"]
    assert projected["defaults"]["vpn"] == "ntgen_b"
    assert providers == {"ntgen_b": "alpha"}
