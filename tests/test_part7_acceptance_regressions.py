"""Regression checks for privileged Part 7 probe preconditions and diagnostics."""

import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from nord_tools_internal.nordvpn_underlay_install import UnderlayError, _run
from tools.probe_recovery import interrupted_evidence


def test_killed_child_before_first_durable_write_is_not_uncertain(tmp_path: Path):
    assert interrupted_evidence(tmp_path) == []


def test_intent_only_interruption_remains_visible(tmp_path: Path):
    (tmp_path / "operation-intents.json").write_text(
        json.dumps({"operations": [{"operation_id": "a", "outcome": "pending"}]}), encoding="utf-8"
    )
    assert interrupted_evidence(tmp_path) == ["operation a: pending"]


def test_underlay_failure_identifies_step_without_echoing_command_output():
    argv = ["ip", "link", "add", "private-interface", "type", "veth"]
    result = subprocess.CompletedProcess(argv, 2, b"", b"private diagnostics")
    with (
        mock.patch("subprocess.run", return_value=result),
        pytest.raises(UnderlayError, match="underlay step.*link.*add.*exit 2") as error,
    ):
        _run(argv)
    assert "private diagnostics" not in str(error.value)


def test_restoration_fixture_uses_valid_pinned_server():
    source = (Path(__file__).resolve().parents[1] / "tools" / "probe_restore_startup.py").read_text()
    assert '"server": "uk715"' in source
    assert '"server": "probe"' not in source


def test_restoration_probe_uses_independent_retirement_descriptor():
    source = (Path(__file__).resolve().parents[1] / "tools" / "probe_restore_startup.py").read_text()
    assert "os.dup(descriptor.fileno())" in source
    assert "owned.release()" in source
