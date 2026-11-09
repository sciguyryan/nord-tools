"""The concurrent application lifecycle probe requires privileged opt-in."""

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import probe_concurrent_application_lifecycle as probe


SCRIPT = Path(probe.__file__).resolve()


def test_preview_is_non_mutating():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "DRY RUN:" in result.stdout
    assert "shared, isolated and direct" in result.stdout


def test_privileged_probe_requires_nonroot_identity():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--run-privileged"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "uid" in result.stderr and "gid" in result.stderr


def test_direct_evidence_requires_host_namespace_and_empty_groups():
    report = {
        "pid": 123,
        "uid": 1000,
        "gid": 1000,
        "groups": [],
        "namespace_device": 5,
        "namespace_inode": 10,
        "executable": "/usr/bin/python",
    }
    namespace = SimpleNamespace(st_dev=5, st_ino=10)
    probe.verify_direct_launch(report, uid=1000, gid=1000, host_namespace=namespace, executable="/usr/bin/python")


def test_direct_evidence_rejects_supplementary_groups():
    report = {
        "pid": 123,
        "uid": 1000,
        "gid": 1000,
        "groups": [10],
        "namespace_device": 5,
        "namespace_inode": 10,
        "executable": "/usr/bin/python",
    }
    namespace = SimpleNamespace(st_dev=5, st_ino=10)
    with pytest.raises(probe.ProbeError):
        probe.verify_direct_launch(
            report,
            uid=1000,
            gid=1000,
            host_namespace=namespace,
            executable="/usr/bin/python",
        )


@pytest.mark.parametrize(
    ("leases", "expected"),
    [
        ([{"application": "shared-a", "allocation_key": "profile:shared"}], {"shared-a": "profile:shared"}),
        ([], {}),
    ],
)
def test_exact_runtime_lease_membership_accepts_expected(leases, expected):
    probe.verify_exact_leases(leases, expected)


@pytest.mark.parametrize(
    "leases",
    [
        [],
        [{"application": "direct-a", "allocation_key": "profile:shared"}],
        [{"application": "shared-a", "allocation_key": "wrong"}],
        [{"application": "shared-a", "allocation_key": "profile:shared"}] * 2,
    ],
)
def test_exact_runtime_lease_membership_rejects_unexpected(leases):
    with pytest.raises(probe.ProbeError):
        probe.verify_exact_leases(leases, {"shared-a": "profile:shared"})


def test_failure_recovery_refuses_when_leases_remain(monkeypatch, tmp_path):
    def blocked(*args, **kwargs):
        raise probe.ProbeError("live lease remains")

    monkeypatch.setattr(probe, "wait_for_lease_release", blocked)
    monkeypatch.setattr(probe, "plan_cleanup", lambda *a, **k: pytest.fail("must not retire live allocation"))
    result = probe.recover_failed_allocations(
        tmp_path / "journal", tmp_path / "bindings", tmp_path / "intents", tmp_path / "leases", {}, ("shared",)
    )
    assert "refused" in result


def test_failure_recovery_uses_owned_profiles_and_lease_evidence(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(probe, "wait_for_lease_release", lambda *a, **k: None)
    monkeypatch.setattr(probe, "plan_cleanup", lambda *a, **k: calls.append((a, k)))
    paths = tuple(tmp_path / name for name in ("journal", "bindings", "intents", "leases"))
    assert "completed" in probe.recover_failed_allocations(*paths, {}, ("shared", "ntiso_a"))
    assert calls[0][1]["selected_profiles"] == ("shared", "ntiso_a")
    assert calls[0][1]["runtime_consumers_path"] == paths[3]
    assert calls[0][1]["execute"] is True


def test_child_watchdog_allows_slow_privileged_acceptance(tmp_path):
    script = tmp_path / "child.py"
    probe.write_child_script(script)
    assert "time.monotonic() + 300" in script.read_text()
