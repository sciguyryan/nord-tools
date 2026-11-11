"""Reference-store lock coverage for cleanup and transition coordination."""

from concurrent.futures import ThreadPoolExecutor
import fcntl
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from nord_tools_internal.nordvpn_consumer_reference_store import (
    ConsumerReferenceError,
    locked_consumer_references,
)


class ReferenceLockTests(unittest.TestCase):
    def test_serialises_cooperating_operations(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "references.json"
            entered = threading.Event()
            release = threading.Event()
            acquired = threading.Event()

            def first():
                with locked_consumer_references(path):
                    entered.set()
                    self.assertTrue(release.wait(5))

            def second():
                with locked_consumer_references(path):
                    acquired.set()

            with ThreadPoolExecutor(max_workers=2) as executor:
                future = executor.submit(first)
                self.assertTrue(entered.wait(5))
                waiting = executor.submit(second)
                self.assertFalse(acquired.wait(0.1))
                release.set()
                future.result(timeout=5)
                waiting.result(timeout=5)
                self.assertTrue(acquired.is_set())

    def test_refuses_world_readable_lock(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "references.json"
            lock = Path(directory) / "references.json.lock"
            lock.write_text("")
            lock.chmod(0o644)
            with self.assertRaises(ConsumerReferenceError), locked_consumer_references(path):
                self.fail("unsafe lock was accepted")

    def test_refuses_symlink_lock(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "references.json"
            (Path(directory) / "references.json.lock").symlink_to(Path(directory) / "target")
            with self.assertRaises(ConsumerReferenceError), locked_consumer_references(path):
                self.fail("symlink lock was accepted")

    def test_refuses_writable_parent_before_creating_lock(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "leases"
            root.mkdir(mode=0o700)
            root.chmod(0o770)
            try:
                path = root / "references.json"
                with (
                    self.assertRaisesRegex(ConsumerReferenceError, "unsafe reference transition directory"),
                    locked_consumer_references(path),
                ):
                    self.fail("unsafe parent was accepted")
                self.assertFalse((root / "references.json.lock").exists())
            finally:
                root.chmod(0o700)

    def test_refuses_hardlinked_lock(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "references.json"
            lock = Path(directory) / "references.json.lock"
            lock.write_text("")
            lock.chmod(0o600)
            os.link(lock, Path(directory) / "other.lock")
            with (
                self.assertRaisesRegex(ConsumerReferenceError, "unsafe reference transition lock"),
                locked_consumer_references(path),
            ):
                self.fail("hardlinked lock was accepted")

    def test_refuses_lock_replacement_after_acquisition(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "references.json"
            lock = Path(directory) / "references.json.lock"
            original_flock = fcntl.flock

            def replace_lock(descriptor, operation):
                original_flock(descriptor, operation)
                lock.rename(Path(directory) / "old.lock")
                lock.write_text("")
                lock.chmod(0o600)

            with (
                patch(
                    "nord_tools_internal.nordvpn_consumer_reference_store.fcntl.flock",
                    side_effect=replace_lock,
                ),
                self.assertRaisesRegex(ConsumerReferenceError, "reference transition lock was replaced"),
                locked_consumer_references(path),
            ):
                self.fail("replacement lock was accepted")

    def test_refuses_parent_replacement_after_acquisition(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "leases"
            root.mkdir(mode=0o700)
            path = root / "references.json"
            moved = Path(directory) / "old-leases"
            original_flock = fcntl.flock

            def replace_parent(descriptor, operation):
                original_flock(descriptor, operation)
                root.rename(moved)
                root.mkdir(mode=0o700)

            with (
                patch(
                    "nord_tools_internal.nordvpn_consumer_reference_store.fcntl.flock",
                    side_effect=replace_parent,
                ),
                self.assertRaisesRegex(ConsumerReferenceError, "reference transition directory was replaced"),
                locked_consumer_references(path),
            ):
                self.fail("replacement directory was accepted")
