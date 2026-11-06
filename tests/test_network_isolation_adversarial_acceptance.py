"""Behavioural tests for the Part 4 adversarial acceptance orchestrator."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import probe_network_isolation_adversarial_acceptance as acceptance  # noqa: E402


def test_dry_run_has_no_observation_or_mutation(capsys):
    with (
        patch.object(acceptance, "observe") as observer,
        patch.object(acceptance.subprocess, "run") as runner,
    ):
        assert acceptance.main([]) == 0
    observer.assert_not_called()
    runner.assert_not_called()
    assert "No host observations or privileged probes executed" in capsys.readouterr().out


def test_success_checks_host_before_and_after():
    with (
        patch.object(acceptance, "observe", side_effect=[{"routes": "same"}, {"routes": "same"}]) as observer,
        patch.object(acceptance, "verify") as verifier,
        patch.object(acceptance.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as runner,
    ):
        assert acceptance.run_acceptance(python="python")
    assert runner.call_args_list == [
        call(["python", str(ROOT / "tools" / filename), flag], check=False) for _, filename, flag in acceptance.STAGES
    ]
    assert observer.call_count == 2
    verifier.assert_called_once_with({"routes": "same"}, {"routes": "same"})


def test_child_failure_stops_but_still_verifies_host():
    with (
        patch.object(acceptance, "observe", return_value={"state": "ok"}) as observer,
        patch.object(acceptance, "verify") as verifier,
        patch.object(acceptance.subprocess, "run", return_value=subprocess.CompletedProcess([], 3)) as runner,
    ):
        assert not acceptance.run_acceptance()
    assert runner.call_count == 1
    assert observer.call_count == 2
    verifier.assert_called_once()


def test_spawn_failure_still_verifies_host():
    with (
        patch.object(acceptance, "observe", return_value={"state": "ok"}) as observer,
        patch.object(acceptance, "verify") as verifier,
        patch.object(acceptance.subprocess, "run", side_effect=OSError("missing")),
    ):
        assert not acceptance.run_acceptance()
    assert observer.call_count == 2
    verifier.assert_called_once()


def test_host_drift_rejects_otherwise_successful_matrix():
    with (
        patch.object(acceptance, "observe", side_effect=[{"state": "before"}, {"state": "after"}]),
        patch.object(acceptance, "verify", side_effect=RuntimeError("drift")),
        patch.object(acceptance.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)),
    ):
        assert not acceptance.run_acceptance()


def test_initial_observation_failure_runs_no_children():
    with (
        patch.object(acceptance, "observe", side_effect=RuntimeError("unavailable")),
        patch.object(acceptance.subprocess, "run") as runner,
    ):
        assert not acceptance.run_acceptance()
    runner.assert_not_called()


def test_requires_explicit_root_authorisation():
    with patch.object(acceptance.os, "geteuid", return_value=1000):
        try:
            acceptance.main(["--run-privileged"])
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError("Expected root refusal")
