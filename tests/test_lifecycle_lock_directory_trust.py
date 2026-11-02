"""Reject writable or foreign-owned lifecycle lock parents before opening the lock."""

import os
from pathlib import Path

import pytest

from nord_tools_internal.nordvpn_execution_lock import lifecycle_execution_lock
from nord_tools_internal.nordvpn_registry import RegistryError


def test_group_writable_lock_directory_is_rejected(tmp_path: Path):
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    directory.chmod(0o770)
    try:
        with (
            pytest.raises(RegistryError, match="unsafe lifecycle execution directory"),
            lifecycle_execution_lock(directory / "lifecycle.json"),
        ):
            pytest.fail("unsafe directory must never acquire a lock")
        assert not (directory / "lifecycle.json.restore.lock").exists()
    finally:
        directory.chmod(0o700)


def test_other_writable_lock_directory_is_rejected(tmp_path: Path):
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    directory.chmod(0o707)
    try:
        with (
            pytest.raises(RegistryError, match="unsafe lifecycle execution directory"),
            lifecycle_execution_lock(directory / "lifecycle.json"),
        ):
            pytest.fail("unsafe directory must never acquire a lock")
    finally:
        directory.chmod(0o700)


def test_private_lock_directory_remains_usable(tmp_path: Path):
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    with lifecycle_execution_lock(directory / "lifecycle.json"):
        lock = directory / "lifecycle.json.restore.lock"
        assert lock.is_file()
        assert lock.stat().st_uid == os.geteuid()
