"""Fail-closed operation intent validation tests."""

import unittest

from nord_tools_internal.nordvpn_identity import allocate_identity
from nord_tools_internal.nordvpn_lifecycle import record_transition
from nord_tools_internal.nordvpn_operation_intent import begin_intent, inspect_intents, resolve_intent, validate_intents
from nord_tools_internal.nordvpn_registry import RegistryError


class OperationIntentTests(unittest.TestCase):
    def setUp(self):
        allocation = allocate_identity("interface", "nt-intent0", "default")
        self.token = allocation["allocation_id"]
        journal = {"version": 1, "allocations": {"version": 2, "resources": [allocation]}, "events": []}
        self.journal = record_transition(record_transition(journal, self.token, "reserved"), self.token, "creating")
        self.empty = {"version": 1, "operations": []}

    def test_begin_and_resolve(self):
        started = begin_intent(self.empty, self.journal, self.token, "create")
        self.assertEqual(len(started["operations"]), 1)
        self.assertEqual(started["operations"][0]["journal_sequence"], 2)
        resolved = resolve_intent(started, self.journal, started["operations"][0]["operation_id"], "completed")
        self.assertEqual(inspect_intents(resolved, self.journal)["unresolved"], [])
        self.assertFalse(inspect_intents(resolved, self.journal)["ownership_verified"])
        self.assertFalse(inspect_intents(resolved, self.journal)["safe_to_delete"])

    def test_reject_duplicate_pending(self):
        started = begin_intent(self.empty, self.journal, self.token, "create")
        with self.assertRaises(RegistryError):
            begin_intent(started, self.journal, self.token, "create")

    def test_reject_duplicate_operation_id(self):
        started = begin_intent(self.empty, self.journal, self.token, "create")
        started["operations"].append(dict(started["operations"][0]))
        with self.assertRaises(RegistryError):
            validate_intents(started, self.journal)

    def test_reject_wrong_transition(self):
        with self.assertRaises(RegistryError):
            begin_intent(self.empty, self.journal, self.token, "retire")

    def test_reject_mismatched_sequence(self):
        started = begin_intent(self.empty, self.journal, self.token, "create")
        started["operations"][0]["journal_sequence"] = 1
        with self.assertRaises(RegistryError):
            validate_intents(started, self.journal)

    def test_uncertain_requires_review(self):
        started = begin_intent(self.empty, self.journal, self.token, "create")
        uncertain = resolve_intent(started, self.journal, started["operations"][0]["operation_id"], "uncertain")
        self.assertEqual(len(inspect_intents(uncertain, self.journal)["unresolved"]), 1)
        with self.assertRaises(RegistryError):
            begin_intent(uncertain, self.journal, self.token, "create")

    def test_invalid_resolution_and_immutable_input(self):
        started = begin_intent(self.empty, self.journal, self.token, "create")
        with self.assertRaises(RegistryError):
            resolve_intent(started, self.journal, started["operations"][0]["operation_id"], "unknown")
        self.assertEqual(started["operations"][0]["outcome"], "pending")


if __name__ == "__main__":
    unittest.main()
