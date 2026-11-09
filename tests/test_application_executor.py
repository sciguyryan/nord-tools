"""Application execution must be gated behind verified durable authority."""

import os
from unittest.mock import patch

import pytest

from nord_tools_internal import nordvpn_application_executor as executor
from nord_tools_internal.nordvpn_application_executor import launch_provisioned_application
from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError
from nord_tools_internal.nordvpn_launch_gate import main as gate_main
from tests.test_application_plan import POLICY


def test_launcher_selects_active_namespace_without_retired_history():
    journal = {
        "allocations": {
            "resources": [
                {
                    "allocation_id": "retired",
                    "profile": "alpha",
                    "kind": "namespace",
                    "identifier": "nt-retired",
                },
                {
                    "allocation_id": "active",
                    "profile": "alpha",
                    "kind": "namespace",
                    "identifier": "nt-active",
                },
            ]
        },
        "events": [
            {"allocation_id": "retired", "state": "retired"},
            {"allocation_id": "active", "state": "active"},
        ],
    }
    with (
        patch.object(executor, "read_private_json", return_value=journal),
        patch.object(executor, "validate_journal", return_value=journal),
    ):
        assert executor._namespace_for_profile("journal.json", "alpha") == "nt-active"


def test_launcher_refuses_multiple_active_profile_namespaces():
    journal = {
        "allocations": {
            "resources": [
                {
                    "allocation_id": allocation,
                    "profile": "alpha",
                    "kind": "namespace",
                    "identifier": f"nt-{allocation}",
                }
                for allocation in ("one", "two")
            ]
        },
        "events": [{"allocation_id": allocation, "state": "active"} for allocation in ("one", "two")],
    }
    with (
        patch.object(executor, "read_private_json", return_value=journal),
        patch.object(executor, "validate_journal", return_value=journal),
        pytest.raises(ConsumerReferenceError, match="unique namespace"),
    ):
        executor._namespace_for_profile("journal.json", "alpha")


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


def test_generation_launch_refuses_missing_tunnel_plan_before_process_creation():
    with (
        patch("nord_tools_internal.nordvpn_application_executor.os.geteuid", return_value=0),
        patch("nord_tools_internal.nordvpn_application_executor.subprocess.Popen") as popen,
        pytest.raises(ConsumerReferenceError, match="pinned tunnel plan"),
    ):
        launch_provisioned_application(
            POLICY,
            "browser",
            (),
            runtime_consumers="x",
            journal_path="x",
            bindings_path="x",
            intent_path="x",
            observe=lambda: {},
            uid=1000,
            gid=1000,
            handover_path="/state/handover.json",
        )
    popen.assert_not_called()


def test_generation_drift_blocks_pre_exec_release_after_lease_reservation():
    from contextlib import nullcontext
    from types import SimpleNamespace

    class SuspendedChild:
        pid = 9876

        def __init__(self, argv, **kwargs):
            os.write(int(argv[7]), b"R")
            self.terminated = False

        def poll(self):
            return None if not self.terminated else -15

        def terminate(self):
            self.terminated = True

        def wait(self):
            return -15

    plan = SimpleNamespace(
        profile="alpha",
        allocation_key="profile:alpha",
        sharing="shared",
        executable="/bin/true",
        arguments=(),
    )
    allocation = SimpleNamespace(
        profile="alpha",
        allocation_key="profile:alpha",
        kernel_profile="ntgen_b",
        generation_id="b",
    )
    journal = {"allocations": {"resources": [{"profile": "ntgen_b", "kind": "namespace", "identifier": "nt-12345678"}]}}
    with (
        patch("nord_tools_internal.nordvpn_application_executor.os.geteuid", return_value=0),
        patch("nord_tools_internal.nordvpn_application_executor.plan_application", return_value=plan),
        patch("nord_tools_internal.nordvpn_application_executor.selected_allocation", return_value=allocation),
        patch("nord_tools_internal.nordvpn_application_executor.read_handover", return_value={}),
        patch("nord_tools_internal.nordvpn_application_executor._namespace_for_profile", return_value="nt-12345678"),
        patch("nord_tools_internal.nordvpn_application_executor.lifecycle_execution_lock", return_value=nullcontext()),
        patch(
            "nord_tools_internal.nordvpn_application_executor.locked_consumer_references", return_value=nullcontext()
        ),
        patch("nord_tools_internal.nordvpn_application_executor.subprocess.Popen", side_effect=SuspendedChild),
        patch("nord_tools_internal.nordvpn_application_executor.reserve_staged_consumer") as reserve,
        patch("nord_tools_internal.nordvpn_application_executor.release_exited_consumer") as release,
        patch("nord_tools_internal.nordvpn_application_executor.read_private_json", return_value=journal),
        patch("nord_tools_internal.nordvpn_application_executor.validate_journal", return_value=journal),
        patch(
            "nord_tools_internal.nordvpn_application_executor._verify_live_confinement",
            side_effect=ValueError("route drift"),
        ),
        patch("nord_tools_internal.nordvpn_application_executor._packet_ready") as packet,
        pytest.raises(ValueError, match="route drift"),
    ):
        launch_provisioned_application(
            POLICY,
            "browser",
            (),
            runtime_consumers="x",
            journal_path="x",
            bindings_path="x",
            intent_path="x",
            observe=lambda: {},
            uid=1000,
            gid=1000,
            handover_path="/state/handover.json",
            tunnel_plan={"endpoint_address": "198.51.100.1", "dns_servers": ["10.0.0.1"]},
        )
    reserve.assert_called_once()
    release.assert_called_once()
    packet.assert_not_called()
