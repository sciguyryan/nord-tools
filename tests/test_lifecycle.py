"""Adversarial tests for the non-authoritative lifecycle journal."""

import json
from pathlib import Path
import tempfile
import unittest

from nord_tools_internal.nordvpn_lifecycle import inspect_lifecycle, record_transition, validate_journal, write_journal
from nord_tools_internal.nordvpn_registry import RegistryError


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.token = "a" * 32
        self.resource = {
            "kind": "interface",
            "identifier": "nt0",
            "profile": "default",
            "owner": "nord-tools",
            "allocation_id": self.token,
        }
        self.journal = {"version": 1, "allocations": {"version": 2, "resources": [self.resource]}, "events": []}

    def test_valid_lifecycle(self):
        current = self.journal
        for state in ("reserved", "creating", "active", "degraded", "active", "retiring", "retired"):
            current = record_transition(current, self.token, state)
        self.assertEqual(len(validate_journal(current)["events"]), 7)
        self.assertEqual(self.journal["events"], [])

    def test_rejects_invalid_transitions(self):
        with self.assertRaises(RegistryError):
            record_transition(self.journal, self.token, "active")
        reserved = record_transition(self.journal, self.token, "reserved")
        with self.assertRaises(RegistryError):
            record_transition(reserved, self.token, "retired")
        with self.assertRaises(RegistryError):
            record_transition(reserved, "b" * 32, "creating")

    def test_detects_replay_and_identity_tampering(self):
        current = record_transition(self.journal, self.token, "reserved")
        duplicate = {**current, "events": current["events"] * 2}
        with self.assertRaises(RegistryError):
            validate_journal(duplicate)
        changed = json.loads(json.dumps(current))
        changed["allocations"]["resources"][0]["identifier"] = "nt1"
        with self.assertRaises(RegistryError):
            validate_journal(changed)

    def test_unverified_and_conflicting_observations(self):
        self.assertFalse(inspect_lifecycle(self.journal)["safe_to_delete"])
        conflict = inspect_lifecycle(
            self.journal, [{"kind": "interface", "identifier": "nt0", "allocation_id": "b" * 32}]
        )
        self.assertEqual(conflict["resources"][0]["finding"], "identity_conflict")
        self.assertFalse(conflict["ownership_verified"])
        matching = inspect_lifecycle(
            self.journal, [{"kind": "interface", "identifier": "nt0", "allocation_id": self.token}]
        )
        self.assertEqual(matching["resources"][0]["finding"], "claimed_not_verified")

    def test_atomic_write_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.json"
            write_journal(path, self.journal)
            self.assertEqual(json.loads(path.read_text()), self.journal)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            link = Path(directory) / "alias.json"
            link.symlink_to(path)
            with self.assertRaises(RegistryError):
                write_journal(link, self.journal)
