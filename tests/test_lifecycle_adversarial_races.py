"""Deterministic adversarial checks for the cooperating lifecycle lock boundary.

These tests simulate pathname substitution at the precise point where a lock
acquisition has completed. They do not claim to exclude independent privileged
actors capable of ignoring the lock or changing kernel resources.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nord_tools_internal.nordvpn_execution_lock import lifecycle_execution_lock
from nord_tools_internal.nordvpn_registry import RegistryError


class LifecycleAdversarialRaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name) / "authority"
        self.parent.mkdir(mode=0o700)
        self.journal = self.parent / "journal.json"

    def test_replacing_lock_inode_during_acquisition_refuses_execution(self):
        import fcntl

        original = fcntl.flock
        attempted = []

        def substitute(fd, operation):
            original(fd, operation)
            lock = self.parent / "journal.json.restore.lock"
            lock.unlink()
            lock.write_bytes(b"")
            lock.chmod(0o600)

        with (
            patch("nord_tools_internal.nordvpn_execution_lock.fcntl.flock", side_effect=substitute),
            self.assertRaisesRegex(RegistryError, "lock identity changed"),
            lifecycle_execution_lock(self.journal),
        ):
            attempted.append(True)
        self.assertEqual(attempted, [])

    def test_replacing_parent_directory_during_acquisition_refuses_execution(self):
        import fcntl

        original = fcntl.flock
        attempted = []

        def substitute(fd, operation):
            original(fd, operation)
            self.parent.rename(self.parent.with_name("retired"))
            self.parent.mkdir(mode=0o700)

        with (
            patch("nord_tools_internal.nordvpn_execution_lock.fcntl.flock", side_effect=substitute),
            self.assertRaisesRegex(RegistryError, "directory identity changed"),
            lifecycle_execution_lock(self.journal),
        ):
            attempted.append(True)
        self.assertEqual(attempted, [])

    def test_replacing_parent_with_symlink_during_acquisition_refuses_execution(self):
        import fcntl

        original = fcntl.flock
        attempted = []

        def substitute(fd, operation):
            original(fd, operation)
            retired = self.parent.with_name("retired")
            self.parent.rename(retired)
            self.parent.symlink_to(retired, target_is_directory=True)

        with (
            patch("nord_tools_internal.nordvpn_execution_lock.fcntl.flock", side_effect=substitute),
            self.assertRaises(RegistryError),
            lifecycle_execution_lock(self.journal),
        ):
            attempted.append(True)
        self.assertEqual(attempted, [])

    def test_insecure_parent_never_creates_lock(self):
        self.parent.chmod(0o777)
        with (
            self.assertRaisesRegex(RegistryError, "unsafe lifecycle execution directory"),
            lifecycle_execution_lock(self.journal),
        ):
            self.fail("untrusted authority directory entered")
        self.assertFalse((self.parent / "journal.json.restore.lock").exists())

    def test_hardlinked_lock_is_not_authorised(self):
        lock = self.parent / "journal.json.restore.lock"
        lock.touch(mode=0o600)
        os.link(lock, self.parent / "other")
        with (
            self.assertRaisesRegex(RegistryError, "unsafe lifecycle execution lock"),
            lifecycle_execution_lock(self.journal),
        ):
            self.fail("hardlinked lock entered")
