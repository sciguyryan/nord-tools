"""Reference-store lock coverage for cleanup and transition coordination."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest

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
