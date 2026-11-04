"""Persisted consumer evidence must be complete and policy-consistent."""

import copy
import json
import tempfile
from pathlib import Path
import unittest

from nord_tools_internal.nordvpn_consumer_reference_store import (
    ConsumerReferenceError,
    read_consumer_references,
    validate_consumer_references,
    write_consumer_references,
)
from nord_tools_internal.nordvpn_sharing_contract import resolve_ownership_groups
from tests.test_application_plan import POLICY


def snapshot():
    return {
        "version": 1,
        "consumers": [
            {"application": name, "profile": group.profile, "allocation_key": group.allocation_key, "active": True}
            for group in resolve_ownership_groups(POLICY)
            for name in group.consumers
        ],
    }


class ConsumerReferenceStoreTests(unittest.TestCase):
    def test_round_trip_and_deterministic_order(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "references.json"
            original = snapshot()
            original["consumers"].reverse()
            write_consumer_references(path, POLICY, original)
            observed = read_consumer_references(path, POLICY)
            self.assertEqual([x["application"] for x in observed["consumers"]], sorted(POLICY["applications"]))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text()), observed)

    def test_missing_unknown_duplicate_and_mismatched_references_fail_closed(self):
        for mutation in ("missing", "unknown", "duplicate", "profile", "key", "active", "version"):
            with self.subTest(mutation=mutation):
                data = snapshot()
                if mutation == "missing":
                    data["consumers"].pop()
                elif mutation == "unknown":
                    data["consumers"][0]["application"] = "unknown"
                elif mutation == "duplicate":
                    data["consumers"].append(copy.deepcopy(data["consumers"][0]))
                elif mutation == "profile":
                    data["consumers"][0]["profile"] = "nonexistent"
                elif mutation == "key":
                    data["consumers"][0]["allocation_key"] = "other"
                elif mutation == "active":
                    data["consumers"][0]["active"] = 1
                else:
                    data["version"] = 2
                with self.assertRaises(ConsumerReferenceError):
                    validate_consumer_references(POLICY, data)

    def test_missing_and_symlinked_files_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "references.json"
            with self.assertRaises(ConsumerReferenceError):
                read_consumer_references(path, POLICY)
            write_consumer_references(path, POLICY, snapshot())
            alias = Path(folder) / "alias.json"
            alias.symlink_to(path)
            with self.assertRaises(ConsumerReferenceError):
                read_consumer_references(alias, POLICY)
