"""Registered direct and VPN-bound packet acceptance contracts."""

import os
from pathlib import Path
import py_compile
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tools import probe_registered_application_confinement as probe


SCRIPT = Path(probe.__file__).resolve()


def test_preview_is_non_mutating():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "DRY RUN:" in result.stdout
    assert "registered direct and VPN-bound" in result.stdout


def test_privileged_probe_requires_nonroot_identity():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--run-privileged"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "uid" in result.stderr and "gid" in result.stderr


def test_generated_registered_child_is_valid_python(tmp_path):
    child = tmp_path / "child.py"
    probe.write_child(child)
    py_compile.compile(str(child), doraise=True)


def test_direct_evidence_requires_host_namespace_and_dropped_groups():
    namespace = os.stat("/proc/self/ns/net")
    report = {
        "pid": 123,
        "uid": 1000,
        "gid": 1000,
        "groups": [],
        "namespace_device": namespace.st_dev,
        "namespace_inode": namespace.st_ino,
        "executable": "/usr/bin/python",
    }
    probe.verify_direct_evidence(report, uid=1000, gid=1000, executable="/usr/bin/python")


def test_direct_evidence_rejects_supplementary_groups():
    namespace = os.stat("/proc/self/ns/net")
    report = {
        "pid": 123,
        "uid": 1000,
        "gid": 1000,
        "groups": [10],
        "namespace_device": namespace.st_dev,
        "namespace_inode": namespace.st_ino,
        "executable": "/usr/bin/python",
    }
    with pytest.raises(probe.RegisteredConfinementError, match="identity"):
        probe.verify_direct_evidence(report, uid=1000, gid=1000, executable="/usr/bin/python")


@pytest.mark.parametrize(
    "leases",
    [
        [],
        [{"application": "direct-probe"}],
        [{"application": "vpn-probe"}, {"application": "vpn-probe"}],
    ],
)
def test_exact_lease_check_rejects_missing_wrong_or_duplicate_membership(leases):
    with pytest.raises(probe.RegisteredConfinementError, match="exactly"):
        probe.verify_only_vpn_lease(leases)


def test_exact_lease_check_accepts_only_vpn_child():
    probe.verify_only_vpn_lease([{"application": "vpn-probe", "generation_id": "unversioned"}])


def test_tunnel_loss_requires_failed_child_dns():
    with pytest.raises(probe.RegisteredConfinementError, match="unexpectedly succeeded"):
        probe.require_failure({"ok": True}, "IPv4 DNS")


def test_acceptance_composes_registered_policy_with_production_fixture():
    context = SimpleNamespace(marker="context")

    def production_probe(**kwargs):
        assert kwargs["applications"] == {
            "vpn-probe": {"executable": str(Path(sys.executable).resolve()), "vpn": "alpha"},
            "direct-probe": {"executable": str(Path(sys.executable).resolve()), "vpn": "direct"},
        }
        kwargs["application_experiment"](context)

    with (
        patch.object(probe, "run_production_probe", side_effect=production_probe),
        patch.object(probe, "application_experiment") as experiment,
    ):
        probe.run_acceptance(1000, 1001)
    experiment.assert_called_once_with(1000, 1001, context)
