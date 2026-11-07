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
from nord_tools_internal.nordvpn_host_linux import _optional_json, _resolver_state
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
