"""Host-default deployment compatibility and refusal coverage."""

from __future__ import annotations

from dataclasses import replace
import json
import subprocess
from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_host_executor import HostProtectionError, inspect_host_compatibility
from nord_tools_internal.nordvpn_host_linux import _inventory, _service_active
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan
from test_host_executor import PLAN, FakeHost
from tools import probe_host_platform_compatibility as probe


def test_supported_profile_report_is_read_only():
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()

    report = inspect_host_compatibility(plan, kernel=fake.kernel())

    assert report == {
        "version": 1,
        "mode": "host_platform_compatibility",
        "supported": True,
        "network_changes_applied": False,
        "underlay_manager": "systemd-networkd",
        "resolver_manager": "systemd-resolved",
        "egress_interface": "eth0",
        "egress_ifindex": 2,
        "conflicts": [],
    }
    assert fake.calls == []


@pytest.mark.parametrize("manager", ["unsupported", "NetworkManager"])
def test_unsupported_underlay_manager_is_refused(manager):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost()
    original = fake.inventory

    def inventory():
        result = original()
        result["underlay_manager"] = manager
        return result

    kernel = replace(fake.kernel(), inventory=inventory)

    with pytest.raises(HostProtectionError, match="requires systemd-networkd"):
        inspect_host_compatibility(plan, kernel=kernel)
    assert fake.calls == []


@pytest.mark.parametrize("returncode", [1, 2, 5])
def test_indeterminate_service_state_fails_closed(returncode):
    response = subprocess.CompletedProcess(["systemctl"], returncode, "", "failed")
    with (
        patch("nord_tools_internal.nordvpn_host_linux.subprocess.run", return_value=response),
        pytest.raises(HostProtectionError, match="indeterminate"),
    ):
        _service_active("NetworkManager.service")


@pytest.mark.parametrize("failure", [OSError("missing"), subprocess.TimeoutExpired("systemctl", 5)])
def test_unavailable_service_inspection_fails_closed(failure):
    with (
        patch("nord_tools_internal.nordvpn_host_linux.subprocess.run", side_effect=failure),
        pytest.raises(HostProtectionError, match="could not be inspected"),
    ):
        _service_active("NetworkManager.service")


def test_missing_or_inactive_service_is_not_a_conflict():
    for returncode in (3, 4):
        response = subprocess.CompletedProcess(["systemctl"], returncode, "", "")
        with patch("nord_tools_internal.nordvpn_host_linux.subprocess.run", return_value=response):
            assert not _service_active("NetworkManager.service")


def test_inventory_reports_competing_service_and_tunnel():
    plan = HostProtectionPlan.from_mapping(PLAN)

    def active(name):
        return name in {"tailscaled.service", "systemd-networkd.service", "systemd-resolved.service"}

    links = [
        {"name": "eth0", "index": 2, "kind": "ether"},
        {"name": "tailscale0", "index": 7, "kind": "tun"},
    ]
    with (
        patch("nord_tools_internal.nordvpn_host_linux._links", return_value=links),
        patch("nord_tools_internal.nordvpn_host_linux._service_active", side_effect=active),
        patch("nord_tools_internal.nordvpn_host_linux._json", return_value=[{"dev": "eth0"}]),
        patch("nord_tools_internal.nordvpn_host_linux._resource_state", return_value="absent"),
        patch("nord_tools_internal.nordvpn_host_linux.read_boot_id", return_value="boot"),
    ):
        inventory = _inventory(plan)

    assert inventory["underlay_manager"] == "systemd-networkd"
    assert inventory["resolver_manager"] == "systemd-resolved"
    assert inventory["conflicts"] == ["tailscaled", "tunnel:tun:tailscale0"]


def test_probe_dry_run_does_not_read_plan_or_inspect(capsys):
    with patch.object(probe, "inspect_host_compatibility") as inspect:
        assert probe.main(["--plan", "missing.json"]) == 0
    inspect.assert_not_called()
    assert "No commands executed" in capsys.readouterr().out


def test_probe_reports_supported_profile(tmp_path, capsys):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(PLAN), encoding="utf-8")
    report = {"mode": "host_platform_compatibility", "supported": True}
    with (
        patch.object(probe.sys, "platform", "linux"),
        patch.object(probe.os, "geteuid", return_value=0),
        patch.object(probe, "inspect_host_compatibility", return_value=report),
    ):
        assert probe.main(["--plan", str(path), "--run-privileged"]) == 0
    assert "host_platform_compatibility" in capsys.readouterr().out
