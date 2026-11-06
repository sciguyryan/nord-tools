"""Behavioural tests for the integrated privileged acceptance runner."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import probe_production_routing_acceptance as acceptance  # noqa: E402


def test_dry_run_never_executes(capsys):
    with patch.object(acceptance.subprocess, "run") as runner:
        assert acceptance.main([]) == 0
    runner.assert_not_called()
    assert "No privileged probes executed" in capsys.readouterr().out


def test_stages_execute_in_order():
    with patch.object(acceptance.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as runner:
        assert acceptance.run_acceptance(python="python")
    assert [call.args[0] for call in runner.call_args_list] == [
        ["python", str(ROOT / "tools" / script), flag] for _, script, flag in acceptance.STAGES
    ]


def test_failure_stops_remaining_stages():
    with patch.object(acceptance.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as runner:
        assert not acceptance.run_acceptance()
    assert runner.call_count == 1


def test_missing_command_fails_closed():
    with patch.object(acceptance.subprocess, "run", side_effect=OSError("missing")):
        assert not acceptance.run_acceptance()


def test_requires_root():
    with patch.object(acceptance.os, "geteuid", return_value=1000):
        try:
            acceptance.main(["--run-privileged"])
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError("Expected privilege refusal")
