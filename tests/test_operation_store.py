"""Durable operation intent store regression tests."""

from pathlib import Path
import tempfile
import unittest

from nord_tools_internal.nordvpn_identity import allocate_identity
from nord_tools_internal.nordvpn_lifecycle import record_transition
from nord_tools_internal.nordvpn_operation_store import initialise_intents, read_intents, update_intent
from nord_tools_internal.nordvpn_registry import RegistryError


class OperationStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "intents.json"
        allocation = allocate_identity("interface", "nt-intent0", "default")
        self.token = allocation["allocation_id"]
        original = {"version": 1, "allocations": {"version": 2, "resources": [allocation]}, "events": []}
        self.journal = record_transition(record_transition(original, self.token, "reserved"), self.token, "creating")

    def test_persist_begin_and_resolve(self):
        initialise_intents(self.path, self.journal)
        started = update_intent(self.path, self.journal, allocation_id=self.token, action="create")
        self.assertEqual(started, read_intents(self.path, self.journal))
        operation_id = started["operations"][0]["operation_id"]
        finished = update_intent(self.path, self.journal, operation_id=operation_id, outcome="uncertain")
        self.assertEqual(finished["operations"][0]["outcome"], "uncertain")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_refuse_overwrite(self):
        initialise_intents(self.path, self.journal)
        with self.assertRaises(RegistryError):
            initialise_intents(self.path, self.journal)

    def test_refuse_symlink(self):
        outside = Path(self.directory.name) / "outside.json"
        outside.write_text("sentinel")
        self.path.symlink_to(outside)
        with self.assertRaises(RegistryError):
            initialise_intents(self.path, self.journal)
        self.assertEqual(outside.read_text(), "sentinel")

    def test_refuse_corrupt_file_without_replacing(self):
        initialise_intents(self.path, self.journal)
        self.path.write_text("corrupt")
        with self.assertRaises(RegistryError):
            update_intent(self.path, self.journal, allocation_id=self.token, action="create")
        self.assertEqual(self.path.read_text(), "corrupt")

    def test_refuse_unsafe_permissions(self):
        initialise_intents(self.path, self.journal)
        self.path.chmod(0o644)
        with self.assertRaises(RegistryError):
            read_intents(self.path, self.journal)

    def test_invalid_update_leaves_existing_state(self):
        initialise_intents(self.path, self.journal)
        original = self.path.read_bytes()
        with self.assertRaises(RegistryError):
            update_intent(self.path, self.journal, allocation_id=self.token, action="retire")
        self.assertEqual(self.path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
