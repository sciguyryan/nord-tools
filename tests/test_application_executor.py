"""Application execution must be gated behind verified durable authority."""

import os
from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_application_executor import launch_provisioned_application
from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError
from nord_tools_internal.nordvpn_launch_gate import main as gate_main
from tests.test_application_plan import POLICY


def test_launcher_requires_root_and_non_root_target():
    with (
        patch("nord_tools_internal.nordvpn_application_executor.os.geteuid", return_value=1000),
        pytest.raises(ConsumerReferenceError, match="privileged launcher"),
    ):
        launch_provisioned_application(
            POLICY,
            "alpha",
            (),
            runtime_consumers="x",
            journal_path="x",
            bindings_path="x",
            intent_path="x",
            observe=lambda: {},
            uid=1000,
            gid=1000,
        )
    with (
        patch("nord_tools_internal.nordvpn_application_executor.os.geteuid", return_value=0),
        pytest.raises(ConsumerReferenceError, match="privileged launcher"),
    ):
        launch_provisioned_application(
            POLICY,
            "alpha",
            (),
            runtime_consumers="x",
            journal_path="x",
            bindings_path="x",
            intent_path="x",
            observe=lambda: {},
            uid=0,
            gid=1000,
        )


def test_launcher_rejects_missing_intent_before_process_creation():
    with (
        patch("nord_tools_internal.nordvpn_application_executor.os.geteuid", return_value=0),
        patch("nord_tools_internal.nordvpn_application_executor.subprocess.Popen") as popen,
        pytest.raises(ConsumerReferenceError, match="intent"),
    ):
        launch_provisioned_application(
            POLICY,
            "alpha",
            (),
            runtime_consumers="x",
            journal_path="x",
            bindings_path="x",
            intent_path="",
            observe=lambda: {},
            uid=1000,
            gid=1000,
        )
    popen.assert_not_called()


def test_gate_refuses_eof_before_exec():
    read_fd, write_fd = os.pipe()
    ready_read, ready_write = os.pipe()
    try:
        os.close(write_fd)
        with (
            patch("sys.argv", ["gate", str(ready_write), str(read_fd), "1000", "1000", "/bin/true"]),
            patch("os.execv") as execute,
        ):
            assert gate_main() == 126
            execute.assert_not_called()
        assert os.read(ready_read, 1) == b"R"
    finally:
        os.close(read_fd)
        os.close(ready_read)


def test_gate_drops_privileges_only_after_release():
    read_fd, write_fd = os.pipe()
    ready_read, ready_write = os.pipe()
    try:
        os.write(write_fd, b"G")
        with (
            patch("sys.argv", ["gate", str(ready_write), str(read_fd), "1000", "1000", "/bin/true", "--flag"]),
            patch("os.setgroups") as groups,
            patch("os.setgid") as gid,
            patch("os.setuid") as uid,
            patch("os.execv") as execute,
        ):
            assert gate_main() == 126
        groups.assert_called_once_with([])
        gid.assert_called_once_with(1000)
        uid.assert_called_once_with(1000)
        execute.assert_called_once_with("/bin/true", ["/bin/true", "--flag"])
        assert os.read(ready_read, 1) == b"R"
    finally:
        os.close(write_fd)
        os.close(ready_read)


def test_gate_rejects_root_target_before_release():
    with patch("sys.argv", ["gate", "5", "6", "0", "1000", "/bin/true"]):
        assert gate_main() == 126
