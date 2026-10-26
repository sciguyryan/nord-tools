"""Adversarial tests for conservative recovery triage."""

import copy
import unittest

from nordvpn_identity import allocate_identity
from nordvpn_lifecycle import record_transition
from nordvpn_recovery import assess_recovery
from nordvpn_registry import RegistryError


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.resource = allocate_identity("interface", "nt-test", "test")
        self.journal = {"version": 1, "allocations": {"version": 2, "resources": [self.resource]}, "events": []}
        self.recorded = {
            "version": 1,
            "resources": [{"allocation_id": self.resource["allocation_id"], "scope": "host", "ifindex": 17}],
        }
        self.observed = {
            "mode": "live_read_only",
            "network_changes_applied": False,
            "host_interfaces": [{"name": "nt-test", "index": 17}],
            "namespaces": [],
            "namespace_details": [],
        }

    def result(self, state=None):
        journal = self.journal
        if state:
            journal = record_transition(journal, self.resource["allocation_id"], "reserved")
            for step in state:
                journal = record_transition(journal, self.resource["allocation_id"], step)
        return assess_recovery(journal, self.recorded, self.observed)

    def test_matching_identity_never_grants_authority(self):
        result = self.result(["creating", "active"])
        self.assertEqual(result["resources"][0]["classification"], "active_claim_unverified")
        self.assertFalse(result["safe_to_delete"])
        self.assertFalse(result["safe_to_modify"])
        self.assertFalse(result["automatic_recovery_permitted"])

    def test_interrupted_creation_requires_review(self):
        self.assertEqual(self.result(["creating"])["resources"][0]["classification"], "interrupted_or_uncertain")

    def test_retired_matching_name_is_suspicious(self):
        self.assertEqual(
            self.result(["creating", "active", "retiring", "retired"])["resources"][0]["classification"],
            "possible_name_reuse",
        )

    def test_reused_index_or_missing_resource_is_not_authority(self):
        for links in ([{"name": "nt-test", "index": 99}], []):
            with self.subTest(links=links):
                observed = {**self.observed, "host_interfaces": links}
                result = assess_recovery(self.journal, self.recorded, observed)
                self.assertEqual(result["resources"][0]["classification"], "identity_drift_or_missing")
                self.assertFalse(result["ownership_verified"])

    def test_missing_recorded_fingerprint_is_insufficient(self):
        result = assess_recovery(self.journal, {"version": 1, "resources": []}, self.observed)
        self.assertEqual(result["resources"][0]["classification"], "insufficient_evidence")

    def test_incomplete_or_forged_observations_rejected(self):
        for mutation in ({"mode": "offline"}, {"network_changes_applied": True}, {"namespace_details": None}):
            with self.subTest(mutation=mutation), self.assertRaises(RegistryError):
                assess_recovery(self.journal, self.recorded, {**self.observed, **mutation})

    def test_malformed_journal_rejected(self):
        journal = copy.deepcopy(self.journal)
        journal["allocations"]["resources"][0]["allocation_id"] = "invalid"
        with self.assertRaises(RegistryError):
            assess_recovery(journal, self.recorded, self.observed)


if __name__ == "__main__":
    unittest.main()
