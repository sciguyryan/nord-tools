"""Adversarial host inspection and interrupted-creation ownership tests."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_host_executor import (
    HostProtectionError,
    activate_host_protection,
    recover_host_protection,
)
from nord_tools_internal.nordvpn_host_linux import _links, _optional_json, _resolver_state, _route_rows, _verify_ready
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan
from nord_tools_internal.nordvpn_host_store import read_host_store
from test_host_executor import BOOT, PLAN, FakeHost


@pytest.mark.parametrize("stderr", ["Operation not permitted", "syntax error", "Permission denied"])
def test_nft_inspection_errors_never_mean_absence(stderr):
    response = subprocess.CompletedProcess(["nft"], 1, "", stderr)
    with (
        patch("nord_tools_internal.nordvpn_host_linux.subprocess.run", return_value=response),
        pytest.raises(HostProtectionError, match="could not establish resource absence"),
    ):
        _optional_json(["nft", "-j", "list", "table", "inet", "nord_tools_host"])


def test_nft_confirmed_missing_table_is_absent():
    response = subprocess.CompletedProcess(["nft"], 1, "", "Error: No such file or directory")
    with patch("nord_tools_internal.nordvpn_host_linux.subprocess.run", return_value=response):
        assert _optional_json(["nft", "-j", "list", "table", "inet", "nord_tools_host"]) is None


@pytest.mark.parametrize("family", [4, 6])
def test_missing_dedicated_route_table_is_certified_absent(family):
    response = subprocess.CompletedProcess(
        ["ip"],
        2,
        "[]\n",
        f"Error: ipv{family}: FIB table does not exist.\nDump terminated\n",
    )
    with patch("nord_tools_internal.nordvpn_host_linux.subprocess.run", return_value=response):
        assert _route_rows(family, 51900) == []


def test_link_inventory_requests_detailed_kind_evidence():
    document = [
        {
            "ifindex": 7,
            "ifname": "ntwg-host",
            "linkinfo": {"info_kind": "wireguard"},
        }
    ]
    with patch("nord_tools_internal.nordvpn_host_linux._json", return_value=document) as inspect:
        assert _links() == [{"name": "ntwg-host", "index": 7, "kind": "wireguard"}]
    inspect.assert_called_once_with(["ip", "-j", "-d", "link", "show"])


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr"),
    [
        (2, "[]\n", "RTNETLINK answers: Operation not permitted\n"),
        (2, "{malformed\n", "Error: ipv4: FIB table does not exist.\nDump terminated\n"),
        (1, "[]\n", "Error: ipv4: FIB table does not exist.\nDump terminated\n"),
    ],
)
def test_route_inspection_errors_never_certify_table_absence(returncode, stdout, stderr):
    response = subprocess.CompletedProcess(["ip"], returncode, stdout, stderr)
    with (
        patch("nord_tools_internal.nordvpn_host_linux.subprocess.run", return_value=response),
        pytest.raises(HostProtectionError),
    ):
        _route_rows(4, 51900)


def test_resolver_failure_with_existing_interface_is_ambiguous():
    plan = HostProtectionPlan.from_mapping(PLAN)
    with (
        patch(
            "nord_tools_internal.nordvpn_host_linux._links",
            return_value=[{"name": plan.interface, "kind": "wireguard"}],
        ),
        patch("nord_tools_internal.nordvpn_host_linux._run", side_effect=HostProtectionError("resolvectl failed")),
    ):
        assert _resolver_state(plan) == "ambiguous"


def test_resolver_missing_interface_is_absent():
    plan = HostProtectionPlan.from_mapping(PLAN)
    with patch("nord_tools_internal.nordvpn_host_linux._links", return_value=[]):
        assert _resolver_state(plan) == "absent"


def test_resolver_reverted_link_is_certified_absent():
    plan = HostProtectionPlan.from_mapping(PLAN)
    link = [{"name": plan.interface, "kind": "wireguard", "index": 9}]
    outputs = [
        f"Link 9 ({plan.interface}):\n",
        f"Link 9 ({plan.interface}):\n",
        f"Link 9 ({plan.interface}): no\n",
    ]
    with (
        patch("nord_tools_internal.nordvpn_host_linux._links", return_value=link),
        patch("nord_tools_internal.nordvpn_host_linux._run", side_effect=outputs),
    ):
        assert _resolver_state(plan) == "absent"


def test_partial_resolver_revert_remains_ambiguous():
    plan = HostProtectionPlan.from_mapping(PLAN)
    link = [{"name": plan.interface, "kind": "wireguard", "index": 9}]
    outputs = [
        f"Link 9 ({plan.interface}): {plan.dns_servers[0]}\n",
        f"Link 9 ({plan.interface}):\n",
        f"Link 9 ({plan.interface}): no\n",
    ]
    with (
        patch("nord_tools_internal.nordvpn_host_linux._links", return_value=link),
        patch("nord_tools_internal.nordvpn_host_linux._run", side_effect=outputs),
    ):
        assert _resolver_state(plan) == "ambiguous"


def test_host_readiness_waits_for_a_fresh_handshake():
    plan = HostProtectionPlan.from_mapping(PLAN)
    with (
        patch("nord_tools_internal.nordvpn_host_linux._resource_state", return_value="present"),
        patch("nord_tools_internal.nordvpn_host_linux._recent_handshake", side_effect=[False, False, True]) as check,
        patch("nord_tools_internal.nordvpn_host_linux.time.monotonic", side_effect=[10.0, 10.1, 10.2]),
        patch("nord_tools_internal.nordvpn_host_linux.time.sleep") as sleep,
    ):
        assert _verify_ready(plan)["handshake"] is True
    assert check.call_count == 3
    assert sleep.call_count == 2


def test_host_readiness_does_not_wait_when_structural_state_is_incomplete():
    plan = HostProtectionPlan.from_mapping(PLAN)
    with (
        patch("nord_tools_internal.nordvpn_host_linux._resource_state", return_value="absent"),
        patch("nord_tools_internal.nordvpn_host_linux._recent_handshake") as check,
    ):
        report = _verify_ready(plan)
    assert report["handshake"] is False
    check.assert_not_called()


def test_recovery_does_not_adopt_matching_foreign_creation(tmp_path):
    plan = HostProtectionPlan.from_mapping(PLAN)
    fake = FakeHost(fail="wireguard")
    store = tmp_path / "host.json"
    with pytest.raises(HostProtectionError):
        activate_host_protection(plan, store, 7, kernel=fake.kernel(), boot_id=BOOT)
    fake.fail = None
    fake.present.add("wireguard")  # A different actor creates a matching resource.
    recovered = recover_host_protection(plan, store, kernel=fake.kernel(), execute=True)
    assert recovered["state"] == "uncertain"
    record = read_host_store(store)["record"]
    assert record["outcome"] == "uncertain"
    assert next(step for step in record["steps"] if step["name"] == "wireguard")["state"] == "uncertain"
    with pytest.raises(HostProtectionError):
        activate_host_protection(plan, store, 7, kernel=fake.kernel(), boot_id=BOOT)


def test_wireguard_retirement_refuses_reused_interface_name():
    from nord_tools_internal.nordvpn_host_linux import _remove_wireguard

    plan = HostProtectionPlan.from_mapping(PLAN)
    with (
        patch(
            "nord_tools_internal.nordvpn_host_linux._wireguard_observation",
            return_value=("present", {"ifindex": 77}),
        ),
        patch("nord_tools_internal.nordvpn_host_linux._run") as run,
        pytest.raises(HostProtectionError, match="identity changed"),
    ):
        _remove_wireguard(plan, {"ifindex": 15})
    run.assert_not_called()


def test_wireguard_retirement_refuses_missing_creation_identity():
    from nord_tools_internal.nordvpn_host_linux import _remove_wireguard

    plan = HostProtectionPlan.from_mapping(PLAN)
    with (
        patch("nord_tools_internal.nordvpn_host_linux._run") as run,
        pytest.raises(HostProtectionError, match="original interface identity"),
    ):
        _remove_wireguard(plan, {})
    run.assert_not_called()
