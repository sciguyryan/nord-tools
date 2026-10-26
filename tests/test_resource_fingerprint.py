"""Conservative resource fingerprint comparison tests."""

import unittest

from nordvpn_registry import RegistryError
from nordvpn_resource_fingerprint import compare_fingerprints


class FingerprintTests(unittest.TestCase):
    def setUp(self):
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
        self.recorded = {"version": 1, "resources": [{"allocation_id": self.token, "scope": "host", "ifindex": 7}]}
        self.observed = {
            "mode": "live_read_only",
            "network_changes_applied": False,
            "namespaces": [],
            "host_interfaces": [{"name": "nt0", "index": 7}],
            "namespace_details": [],
        }

    def compare(self, recorded=None, observed=None):
        return compare_fingerprints(
            self.journal,
            self.recorded if recorded is None else recorded,
            self.observed if observed is None else observed,
        )

    def test_match_never_grants_authority(self):
        result = self.compare()
        self.assertEqual(result["resources"][0]["finding"], "fingerprint_matches_unverified")
        self.assertFalse(result["ownership_verified"])
        self.assertFalse(result["safe_to_delete"])
        self.assertFalse(result["safe_to_modify"])

    def test_index_change(self):
        result = self.compare(observed={**self.observed, "host_interfaces": [{"name": "nt0", "index": 8}]})
        self.assertEqual(result["resources"][0]["finding"], "interface_index_changed")

    def test_missing_interface(self):
        self.assertEqual(
            self.compare(observed={**self.observed, "host_interfaces": []})["resources"][0]["finding"],
            "interface_missing",
        )

    def test_missing_scope(self):
        record = {"version": 1, "resources": [{**self.recorded["resources"][0], "scope": "missing"}]}
        self.assertEqual(self.compare(recorded=record)["resources"][0]["finding"], "scope_missing")

    def test_invalid_snapshots(self):
        for record in (
            {"version": True, "resources": []},
            {"version": 1, "resources": [*self.recorded["resources"], *self.recorded["resources"]]},
            {"version": 1, "resources": [{**self.recorded["resources"][0], "ifindex": True}]},
        ):
            with self.subTest(record=record), self.assertRaises(RegistryError):
                self.compare(recorded=record)

    def test_incomplete_or_duplicate_observations(self):
        for observed in (
            {**self.observed, "network_changes_applied": True},
            {**self.observed, "namespace_details": [{"name": "x", "interfaces": []}]},
            {**self.observed, "host_interfaces": [{"name": "nt0", "index": 7}, {"name": "other", "index": 7}]},
        ):
            with self.subTest(observed=observed), self.assertRaises(RegistryError):
                self.compare(observed=observed)
