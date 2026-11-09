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
