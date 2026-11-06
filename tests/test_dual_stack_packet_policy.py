"""Behavioural checks for the disposable packet acceptance orchestrator."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import probe_dual_stack_packet_policy as acceptance  # noqa: E402


def test_dry_run_does_not_execute(capsys):
    with patch.object(acceptance.subprocess, "run") as runner:
        assert acceptance.main([]) == 0
    runner.assert_not_called()
    assert "No kernel resources created" in capsys.readouterr().out


def test_each_stage_is_run_in_order():
    with patch.object(acceptance.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as runner:
        assert acceptance.run_acceptance(python="python")
    assert [call.args[0][-2:] for call in runner.call_args_list] == [
        [str(ROOT / "tools" / script), "--execute"] for _, script in acceptance.STAGES
    ]


def test_failure_prevents_later_stage():
    with patch.object(acceptance.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as runner:
        assert not acceptance.run_acceptance()
    assert runner.call_count == 1


def test_missing_executable_fails_closed():
    with patch.object(acceptance.subprocess, "run", side_effect=FileNotFoundError("missing")):
        assert not acceptance.run_acceptance()


def test_privileged_mode_refuses_non_root():
    with patch.object(acceptance.os, "geteuid", return_value=1000):
        try:
            acceptance.main(["--run-privileged"])
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError("Expected privilege refusal")
