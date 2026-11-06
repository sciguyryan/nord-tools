"""Non-privileged acceptance command and concurrent direct child contract."""

from unittest.mock import patch

import pytest

from tools import probe_application_network_confinement as probe


def test_preview_does_not_mutate(capsys):
    with patch.object(probe, "observe", side_effect=AssertionError("unexpected observation")):
        assert probe.main([]) == 0
    assert "DRY RUN" in capsys.readouterr().out


def test_privileged_execution_requires_nonroot_identity():
    with patch.object(probe.os, "geteuid", return_value=0), pytest.raises(SystemExit):
        probe.main(["--run-privileged"])


def test_privileged_execution_refuses_nonroot_caller():
    with patch.object(probe.os, "geteuid", return_value=1000), pytest.raises(SystemExit):
        probe.main(["--run-privileged", "--uid", "1001", "--gid", "1001"])


def test_host_integrity_checked_after_concurrent_probe():
    with (
        patch.object(probe.os, "geteuid", return_value=0),
        patch.object(probe.shutil, "which", return_value="/usr/bin/tool"),
        patch.object(probe.Path, "is_dir", return_value=True),
        patch.object(probe, "observe", side_effect=["before", "after"]) as observe,
        patch.object(probe, "concurrent_experiment") as experiment,
        patch.object(probe, "verify") as verify,
    ):
        assert probe.main(["--run-privileged", "--uid", "1000", "--gid", "1000"]) == 0
    experiment.assert_called_once_with(1000, 1000)
    verify.assert_called_once_with("before", "after")
    assert observe.call_count == 2


def test_failed_confinement_refuses_success():
    with (
        patch.object(probe.os, "geteuid", return_value=0),
        patch.object(probe.shutil, "which", return_value="/usr/bin/tool"),
        patch.object(probe.Path, "is_dir", return_value=True),
        patch.object(probe, "observe", return_value={}),
        patch.object(probe, "concurrent_experiment", side_effect=probe.ApplicationNetworkAcceptanceError("blocked")),
    ):
        assert probe.main(["--run-privileged", "--uid", "1000", "--gid", "1000"]) == 1
