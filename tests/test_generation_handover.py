"""Deterministic generation handover storage and transition tests."""

import pytest

from nord_tools_internal.nordvpn_generation_handover import (
    AllocationGeneration,
    GenerationHandoverError,
    advance_handover,
    prepare_handover,
    prepare_generation_handover,
    policy_digest,
    read_handover,
    selected_generation,
    selected_allocation,
    _advance_verified_handover,
)


POLICY = {"vpn": "alpha"}


def test_handover_monotonic_and_restartable(tmp_path):
    path = tmp_path / "handover.json"
    initial = prepare_handover(path, profile="alpha", old="gen-1", replacement="gen-2", policy=POLICY)
    assert selected_generation(initial, policy=POLICY) == "gen-1"
    with pytest.raises(GenerationHandoverError):
        prepare_handover(path, profile="alpha", old="gen-1", replacement="gen-3", policy=POLICY)
    verified = advance_handover(path, expected_phase="prepared", next_phase="verified", policy=POLICY, verified=True)
    assert selected_generation(verified, policy=POLICY) == "gen-1"
    active = advance_handover(path, expected_phase="verified", next_phase="active", policy=POLICY, verified=True)
    assert selected_generation(read_handover(path), policy=POLICY) == "gen-2"
    assert active["phase"] == "active"
    with pytest.raises(GenerationHandoverError):
        advance_handover(
            path, expected_phase="active", next_phase="draining", policy=POLICY, verified=True, old_consumers=1
        )
    drained = advance_handover(
        path, expected_phase="active", next_phase="draining", policy=POLICY, verified=True, old_consumers=0
    )
    assert drained["phase"] == "draining"


@pytest.mark.parametrize("old,new", [("prepared", "active"), ("active", "verified"), ("prepared", "prepared")])
def test_invalid_transition_refused(tmp_path, old, new):
    path = tmp_path / "handover.json"
    prepare_handover(path, profile="alpha", old="gen-1", replacement="gen-2", policy=POLICY)
    with pytest.raises(GenerationHandoverError):
        advance_handover(path, expected_phase=old, next_phase=new, policy=POLICY, verified=True)


def test_changed_policy_and_unverified_transition_refused(tmp_path):
    path = tmp_path / "handover.json"
    prepare_handover(path, profile="alpha", old="gen-1", replacement="gen-2", policy=POLICY)
    with pytest.raises(GenerationHandoverError):
        advance_handover(path, expected_phase="prepared", next_phase="verified", policy=POLICY)
    with pytest.raises(GenerationHandoverError):
        advance_handover(path, expected_phase="prepared", next_phase="verified", policy={"vpn": "other"}, verified=True)
    with pytest.raises(GenerationHandoverError):
        selected_generation(read_handover(path), policy={"vpn": "other"})


def test_corrupt_document_fails_closed(tmp_path):
    path = tmp_path / "handover.json"
    path.write_text('{"version": 1}', encoding="utf-8")
    with pytest.raises(GenerationHandoverError):
        read_handover(path)


def test_allocation_bound_generations_select_exact_kernel_scope(tmp_path):
    path = tmp_path / "handover.json"
    digest = policy_digest(POLICY)
    old = AllocationGeneration("alpha", "profile:alpha", "gen-1", "alpha", digest)
    replacement = AllocationGeneration("alpha", "profile:alpha", "gen-2", "ntgen_abc", digest)
    prepared = prepare_generation_handover(path, old=old, replacement=replacement, policy=POLICY)
    assert selected_allocation(prepared, policy=POLICY) == old
    with pytest.raises(GenerationHandoverError, match="privileged replacement executor"):
        advance_handover(path, expected_phase="prepared", next_phase="verified", policy=POLICY, verified=True)
    _advance_verified_handover(path, expected_phase="prepared", next_phase="verified", policy=POLICY, verified=True)
    active = _advance_verified_handover(
        path, expected_phase="verified", next_phase="active", policy=POLICY, verified=True
    )
    assert selected_allocation(active, policy=POLICY) == replacement


def test_legacy_handover_is_not_reinterpreted_as_allocation_generation(tmp_path):
    path = tmp_path / "handover.json"
    prepared = prepare_handover(path, profile="alpha", old="gen-1", replacement="gen-2", policy=POLICY)
    with pytest.raises(GenerationHandoverError, match="legacy"):
        selected_allocation(prepared, policy=POLICY)
