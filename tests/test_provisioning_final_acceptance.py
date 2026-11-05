"""Behavioural tests for the final privileged acceptance orchestrator."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "tools" / "probe_provisioning_final_acceptance.py"
spec = importlib.util.spec_from_file_location("probe_provisioning_final_acceptance", SOURCE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def test_preview_never_invokes_subprocess(capsys):
    with patch.object(probe.subprocess, "run") as run:
        assert probe.main([]) == 0
    run.assert_not_called()
    assert "DRY RUN" in capsys.readouterr().out


def test_privileged_gate_rejects_unprivileged_caller():
    with patch.object(probe.os, "geteuid", return_value=1000), patch.object(probe, "run_acceptance") as run:
        assert probe.main(["--run-privileged"]) == 2
    run.assert_not_called()


def test_success_runs_both_stages():
    with patch.object(probe.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
        assert probe.run_acceptance(python="python")
    assert [Path(call.args[0][1]).name for call in run.call_args_list] == [stage[1] for stage in probe.STAGES]
    assert all(call.args[0][-1] == "--run-privileged" for call in run.call_args_list)


def test_failure_stops_without_running_next_stage():
    with patch.object(probe.subprocess, "run", return_value=SimpleNamespace(returncode=1)) as run:
        assert not probe.run_acceptance()
    assert run.call_count == 1


def test_execution_error_stops_without_running_next_stage():
    with patch.object(probe.subprocess, "run", side_effect=OSError("unavailable")) as run:
        assert not probe.run_acceptance()
    assert run.call_count == 1
