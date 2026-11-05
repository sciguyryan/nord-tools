"""Regression coverage for later-boundary recovery acceptance orchestration."""

import os
from unittest.mock import patch

import pytest

from tools import probe_later_recovery, probe_recovery


def test_later_recovery_preview_is_non_mutating(capsys):
    with patch.object(probe_later_recovery, "run_acceptance", side_effect=AssertionError("unexpected mutation")):
        assert probe_later_recovery.main([]) == 0
    assert "underlay, wireguard, routing" in capsys.readouterr().out


def test_later_recovery_requires_root():
    with patch.object(probe_later_recovery.os, "geteuid", return_value=1000):
        assert probe_later_recovery.main(["--run-privileged"]) == 2


def test_later_recovery_stops_on_first_failure():
    from subprocess import CompletedProcess

    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return CompletedProcess(command, 1 if len(commands) == 2 else 0)

    with patch.object(probe_later_recovery.subprocess, "run", side_effect=fake_run):
        assert not probe_later_recovery.run_acceptance(python="python")
    assert [command[3] for command in commands] == ["underlay", "wireguard"]


@pytest.mark.parametrize("checkpoint,field", [("wireguard", "configure_wireguard"), ("routing", "route_tunnel")])
def test_checkpoint_wraps_completed_kernel_operation(tmp_path, checkpoint, field):
    from nord_tools_internal import nordvpn_restore_executor as restore

    read_fd, write_fd = os.pipe()
    calls = []

    class Reached(Exception):
        pass

    class FakeKernel:
        def configure_wireguard(self, *args):
            calls.append("wireguard")

        def route_tunnel(self, *args):
            calls.append("routing")

    def fake_main(argv):
        kernel = restore._real_kernel()
        getattr(kernel, field)("example")
        return 0

    # The production surface is a frozen dataclass, so use a real shaped instance.
    kernel = restore.RestoreKernel(*([lambda *args: None] * len(restore.RestoreKernel.__dataclass_fields__)))
    from dataclasses import replace

    kernel = replace(
        kernel, configure_wireguard=FakeKernel().configure_wireguard, route_tunnel=FakeKernel().route_tunnel
    )
    with (
        patch.object(restore, "_real_kernel", return_value=kernel),
        patch.object(probe_recovery.nordvpn_manage, "main", side_effect=fake_main),
        patch.object(probe_recovery.signal, "pause", side_effect=Reached),
        pytest.raises(Reached),
    ):
        probe_recovery.checkpoint_child(str(tmp_path / "startup.json"), write_fd, checkpoint=checkpoint)
    assert calls == [checkpoint]
    assert os.read(read_fd, 1) == b"R"
    os.close(read_fd)
    with pytest.raises(OSError):
        os.fstat(write_fd)


def test_checkpoint_flags_are_mutually_exclusive():
    with pytest.raises(SystemExit) as error:
        probe_recovery.main(["--after-binding", "--checkpoint", "routing"])
    assert error.value.code == 2
