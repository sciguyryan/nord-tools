"""Declared consumer transitions reject stale or incomplete evidence."""

import tempfile
from pathlib import Path
import unittest

from nord_tools_internal.nordvpn_consumer_reference_store import (
    ConsumerReferenceError,
    read_consumer_references,
    transition_consumer_reference,
    write_consumer_references,
)
from tests.test_consumer_reference_store import POLICY, snapshot


class ConsumerReferenceTransitionTests(unittest.TestCase):
    def test_compare_and_swap_and_repeated_transition(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "references.json"
            write_consumer_references(path, POLICY, snapshot())
            name = sorted(POLICY["applications"])[0]
            transition_consumer_reference(path, POLICY, name, expected_active=True, active=False)
            with self.assertRaisesRegex(ConsumerReferenceError, "stale"):
                transition_consumer_reference(path, POLICY, name, expected_active=True, active=False)
            transition_consumer_reference(path, POLICY, name, expected_active=False, active=True)
            self.assertTrue(
                next(x for x in read_consumer_references(path, POLICY)["consumers"] if x["application"] == name)[
                    "active"
                ]
            )

    def test_missing_file_and_unknown_consumer_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "references.json"
            with self.assertRaises(ConsumerReferenceError):
                transition_consumer_reference(path, POLICY, "unknown", expected_active=False, active=True)
            write_consumer_references(path, POLICY, snapshot())
            with self.assertRaises(ConsumerReferenceError):
                transition_consumer_reference(path, POLICY, "unknown", expected_active=False, active=True)

    def test_invalid_transition_state_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "references.json"
            write_consumer_references(path, POLICY, snapshot())
            with self.assertRaises(ConsumerReferenceError):
                transition_consumer_reference(
                    path, POLICY, sorted(POLICY["applications"])[0], expected_active=1, active=False
                )
