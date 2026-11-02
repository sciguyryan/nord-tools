"""Regression checks for the shared lifecycle single-flight boundary."""

import os
from pathlib import Path
import tempfile
import threading
import unittest

from nord_tools_internal.nordvpn_execution_lock import lifecycle_execution_lock
from nord_tools_internal.nordvpn_registry import RegistryError


class ExecutionLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.journal = self.directory / "journal.json"

    def test_lock_remains_after_release(self):
        with lifecycle_execution_lock(self.journal):
            pass
        self.assertTrue((self.directory / "journal.json.restore.lock").is_file())

    def test_symlinked_lock_is_refused(self):
        (self.directory / "journal.json.restore.lock").symlink_to(self.journal)
        with self.assertRaises(RegistryError), lifecycle_execution_lock(self.journal):
            pass

    def test_hardlinked_lock_is_refused(self):
        lock = self.directory / "journal.json.restore.lock"
        lock.write_text("")
        os.chmod(lock, 0o600)
        os.link(lock, self.directory / "other")
        with self.assertRaises(RegistryError), lifecycle_execution_lock(self.journal):
            pass

    def test_insecure_lock_permissions_are_refused(self):
        lock = self.directory / "journal.json.restore.lock"
        lock.write_text("")
        os.chmod(lock, 0o666)
        with self.assertRaises(RegistryError), lifecycle_execution_lock(self.journal):
            pass

    def test_competing_thread_waits_for_release(self):
        entered = threading.Event()
        release = threading.Event()
        second_entered = threading.Event()
        errors = []

        def first():
            try:
                with lifecycle_execution_lock(self.journal):
                    entered.set()
                    if not release.wait(5):
                        raise RuntimeError("release timeout")
            except Exception as exc:
                errors.append(exc)

        def second():
            try:
                with lifecycle_execution_lock(self.journal):
                    second_entered.set()
            except Exception as exc:
                errors.append(exc)

        one = threading.Thread(target=first)
        two = threading.Thread(target=second)
        one.start()
        try:
            self.assertTrue(entered.wait(5))
            two.start()
            self.assertFalse(second_entered.wait(0.05))
        finally:
            release.set()
            one.join(5)
            if two.ident is not None:
                two.join(5)
        self.assertEqual(errors, [])
        self.assertTrue(second_entered.is_set())

    def test_symlinked_parent_is_refused(self):
        alias = self.directory.with_name(self.directory.name + "-alias")
        alias.symlink_to(self.directory, target_is_directory=True)
        self.addCleanup(alias.unlink)
        with self.assertRaises(RegistryError), lifecycle_execution_lock(alias / "journal.json"):
            pass
