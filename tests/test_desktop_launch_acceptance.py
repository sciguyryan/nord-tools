"""Desktop platform acceptance remains explicit and non-mutating by default."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from tools import probe_desktop_launch_acceptance as probe


SCRIPT = Path(probe.__file__).resolve()


def test_preview_is_non_mutating():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "DRY RUN:" in result.stdout
    assert "No network namespace" in result.stdout


def test_privileged_probe_requires_explicit_identity():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--run-privileged"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "uid" in result.stderr and "gid" in result.stderr


def test_report_requires_child_and_descendant_identity_environment_and_endpoints():
    namespace = os.stat("/proc/self/ns/net")
    environment = {"DISPLAY": ":0"}

    def evidence(pid):
        return {
            "pid": pid,
            "uid": 1000,
            "gid": 1000,
            "groups": [],
            "namespace_device": namespace.st_dev,
            "namespace_inode": namespace.st_ino,
            "environment": environment,
        }

    report = {
        **evidence(10),
        "descendant": evidence(11),
        "endpoints": ["wayland", "x11", "dbus", "xauthority"],
    }
    probe.verify_report(report, uid=1000, gid=1000, environment=environment)


@pytest.mark.parametrize(
    ("target", "field", "value"),
    [
        ("parent", "uid", 0),
        ("parent", "groups", [10]),
        ("descendant", "environment", {"LD_PRELOAD": "/tmp/injected"}),
        ("descendant", "namespace_inode", -1),
    ],
)
def test_report_rejects_identity_environment_or_descendant_drift(target, field, value):
    namespace = os.stat("/proc/self/ns/net")
    environment = {"DISPLAY": ":0"}
    evidence = {
        "pid": 10,
        "uid": 1000,
        "gid": 1000,
        "groups": [],
        "namespace_device": namespace.st_dev,
        "namespace_inode": namespace.st_ino,
        "environment": environment,
    }
    report = {
        **evidence,
        "descendant": {**evidence, "pid": 11},
        "endpoints": ["wayland", "x11", "dbus", "xauthority"],
    }
    (report if target == "parent" else report["descendant"])[field] = value
    with pytest.raises(probe.DesktopAcceptanceError, match="differed"):
        probe.verify_report(report, uid=1000, gid=1000, environment=environment)


def test_report_requires_all_selected_desktop_endpoints():
    namespace = os.stat("/proc/self/ns/net")
    evidence = {
        "pid": 10,
        "uid": 1000,
        "gid": 1000,
        "groups": [],
        "namespace_device": namespace.st_dev,
        "namespace_inode": namespace.st_ino,
        "environment": {},
    }
    with pytest.raises(probe.DesktopAcceptanceError, match="endpoint"):
        probe.verify_report(
            {**evidence, "descendant": {**evidence, "pid": 11}, "endpoints": ["wayland"]},
            uid=1000,
            gid=1000,
            environment={},
        )
