"""Tests for cooperating-writer serialisation and conservative failure modes."""

import json
from pathlib import Path
import tempfile
import threading
import unittest

from nordvpn_lifecycle import write_journal
from nordvpn_lifecycle_store import locked_journal, transition_journal, update_journal
from nordvpn_registry import RegistryError


class LifecycleStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "journal.json"
        self.token = "a" * 32
        self.journal = {
            "version": 1,
            "allocations": {
                "version": 2,
                "resources": [
                    {
                        "kind": "interface",
                        "identifier": "nt0",
                        "profile": "default",
                        "owner": "nord-tools",
                        "allocation_id": self.token,
                    }
                ],
            },
            "events": [],
        }
        write_journal(self.path, self.journal)

    def test_transitions_persist_and_keep_stable_lock(self):
        transition_journal(self.path, self.token, "reserved")
        transition_journal(self.path, self.token, "creating")
        self.assertEqual(
            [event["state"] for event in json.loads(self.path.read_text())["events"]], ["reserved", "creating"]
        )
        self.assertTrue(self.path.with_name("journal.json.lock").exists())

    def test_failed_transform_does_not_replace_journal(self):
        before = self.path.read_bytes()
        with self.assertRaises(RegistryError):
            transition_journal(self.path, self.token, "active")
        self.assertEqual(self.path.read_bytes(), before)

    def test_missing_and_corrupt_journal_fail_closed(self):
        self.path.unlink()
        with self.assertRaises(RegistryError):
            transition_journal(self.path, self.token, "reserved")
        self.path.write_text("{")
        with self.assertRaises(RegistryError):
            transition_journal(self.path, self.token, "reserved")

    def test_symlinked_ancestor_and_lock_refused(self):
        alias = Path(self.directory.name) / "alias"
        alias.symlink_to(self.path.parent, target_is_directory=True)
        with self.assertRaises(RegistryError):
            transition_journal(alias / "journal.json", self.token, "reserved")
        lock = self.path.with_name("journal.json.lock")
        lock.symlink_to(self.path)
        with self.assertRaises(RegistryError):
            transition_journal(self.path, self.token, "reserved")

    def test_concurrent_updates_do_not_lose_events(self):
        entered = threading.Event()
        release = threading.Event()
        errors = []

        def slow_update():
            try:

                def transform(journal):
                    entered.set()
                    if not release.wait(3):
                        raise RuntimeError("timed out waiting for test release")
                    from nordvpn_lifecycle import record_transition

                    return record_transition(journal, self.token, "reserved")

                update_journal(self.path, transform)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=slow_update)
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            # The lock is held by the other thread; release before updating.
            release.set()
            transition_journal(self.path, self.token, "creating")
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(json.loads(self.path.read_text())["events"]), 2)

    def test_lock_is_not_removed_after_release(self):
        with locked_journal(self.path):
            pass
        self.assertTrue(self.path.with_name("journal.json.lock").is_file())
