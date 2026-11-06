"""Consolidated privileged application acceptance orchestration regressions."""

import subprocess
from unittest.mock import patch

import pytest

from tools import probe_application_lifecycle_acceptance as probe


def test_preview_never_observes_host_or_runs_children(capsys):
    with (
        patch.object(probe, "observe", side_effect=AssertionError("host observed")),
        patch.object(probe.subprocess, "run", side_effect=AssertionError("child launched")),
    ):
        assert probe.main([]) == 0
    assert "DRY RUN" in capsys.readouterr().out


@pytest.mark.parametrize("uid,gid", [(0, 1000), (1000, 0), (-1, 1000)])
def test_privileged_identity_must_be_nonroot(uid, gid):
    with patch.object(probe.os, "geteuid", return_value=0), pytest.raises(SystemExit):
        probe.main(["--run-privileged", "--uid", str(uid), "--gid", str(gid)])


def test_nonroot_cannot_run_privileged():
    with patch.object(probe.os, "geteuid", return_value=1000), pytest.raises(SystemExit):
        probe.main(["--run-privileged", "--uid", "1000", "--gid", "1000"])


def test_complete_matrix_passes_and_preserves_host():
    with (
        patch.object(probe, "observe", side_effect=["before", "after"]) as observe,
        patch.object(probe, "verify") as verify,
        patch.object(probe.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run,
    ):
        assert probe.run_acceptance(1000, 1000)
    assert run.call_count == len(probe.STAGES)
    assert observe.call_count == 2
    verify.assert_called_once_with("before", "after")
    for call, (_, filename, needs_identity) in zip(run.call_args_list, probe.STAGES):
        command = call.args[0]
        assert command[1].endswith(filename)
        assert ("--uid" in command) is needs_identity
        assert ("--gid" in command) is needs_identity


def test_failed_stage_stops_and_still_verifies_host():
    with (
        patch.object(probe, "observe", side_effect=["before", "after"]),
        patch.object(probe, "verify") as verify,
        patch.object(probe.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run,
    ):
        assert not probe.run_acceptance(1000, 1000)
    assert run.call_count == 1
    verify.assert_called_once_with("before", "after")


def test_host_drift_refuses_success():
    with (
        patch.object(probe, "observe", side_effect=["before", "after"]),
        patch.object(probe, "verify", side_effect=RuntimeError("firewall changed")),
        patch.object(probe.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)),
    ):
        assert not probe.run_acceptance(1000, 1000)


def test_child_start_error_still_verifies_host():
    with (
        patch.object(probe, "observe", side_effect=["before", "after"]),
        patch.object(probe, "verify") as verify,
        patch.object(probe.subprocess, "run", side_effect=OSError("cannot start")),
    ):
        assert not probe.run_acceptance(1000, 1000)
    verify.assert_called_once_with("before", "after")


def test_baseline_failure_does_not_launch_children():
    with (
        patch.object(probe, "observe", side_effect=OSError("no nft")),
        patch.object(probe.subprocess, "run") as run,
    ):
        assert not probe.run_acceptance(1000, 1000)
    run.assert_not_called()
