"""Retirement acceptance must verify absence without issuing a second deletion."""

import subprocess
from unittest import mock

import pytest

from tools.probe_restore_startup import ProbeError, verify_retired_resources


def _link_result(code: int, stderr: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["ip", "link", "show", "dev", "veth-test"], code, b"", stderr)


def test_retired_veth_is_verified_without_deleting_host_link():
    with (
        mock.patch("tools.probe_restore_startup.command", return_value=b"other-namespace\n"),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        mock.patch(
            "tools.probe_restore_startup.subprocess.run", return_value=_link_result(1, b"Device does not exist.")
        ) as run,
    ):
        verify_retired_resources("nt-example", "veth-test")
    run.assert_called_once()
    assert run.call_args.args[0] == ["ip", "link", "show", "dev", "veth-test"]


def test_existing_host_link_is_not_deleted():
    with (
        mock.patch("tools.probe_restore_startup.command", return_value=b""),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        mock.patch("tools.probe_restore_startup.subprocess.run", return_value=_link_result(0)) as run,
        pytest.raises(ProbeError, match="remains"),
    ):
        verify_retired_resources("nt-example", "veth-test")
    run.assert_called_once()


def test_unrelated_namespaces_do_not_block_retirement():
    with (
        mock.patch("tools.probe_restore_startup.command", return_value=b"other-namespace (id: 1)\n"),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        mock.patch("tools.probe_restore_startup.subprocess.run", return_value=_link_result(1, b"Cannot find device")),
    ):
        verify_retired_resources("nt-example", "veth-test")


def test_target_namespace_still_present_is_rejected():
    with (
        mock.patch("tools.probe_restore_startup.command", return_value=b"nt-example (id: 1)\n"),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        pytest.raises(ProbeError, match="namespace remains"),
    ):
        verify_retired_resources("nt-example", "veth-test")


def test_unexplained_ip_failure_is_not_treated_as_absence():
    with (
        mock.patch("tools.probe_restore_startup.command", return_value=b""),
        mock.patch("tools.probe_restore_startup.Path.exists", return_value=False),
        mock.patch("tools.probe_restore_startup.subprocess.run", return_value=_link_result(2, b"permission denied")),
        pytest.raises(ProbeError, match="absence could not be established"),
    ):
        verify_retired_resources("nt-example", "veth-test")
