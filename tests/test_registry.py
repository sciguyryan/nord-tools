"""Adversarial tests for the offline ownership-claim audit."""

import copy
import unittest

from nordvpn_registry import RegistryError, audit_registry, validate_registry


LEDGER = {
    "version": 1,
    "resources": [{"kind": "interface", "identifier": "nt-wg0", "profile": "main", "owner": "nord-tools"}],
}
INVENTORY = {
    "version": 1,
    "profiles": {
        "main": {
            "owner": "nord-tools",
            "state": "ready",
            "configuration": {"selection": {"mode": "country", "country": "GB"}, "sharing": "shared"},
        }
    },
}


class RegistryTests(unittest.TestCase):
    def test_ready_profile_is_not_resource_proof(self):
        result = audit_registry(LEDGER, INVENTORY)
        self.assertEqual(result["findings"][0]["finding"], "unverified_resource")
        self.assertFalse(result["safe_to_delete"])
        self.assertFalse(result["ownership_verified"])

    def test_missing_and_external_profiles(self):
        self.assertEqual(
            audit_registry(LEDGER, {"version": 1, "profiles": {}})["findings"][0]["finding"], "unobserved_profile"
        )
        external = copy.deepcopy(INVENTORY)
        external["profiles"]["main"]["owner"] = "external"
        self.assertEqual(audit_registry(LEDGER, external)["findings"][0]["finding"], "ownership_conflict")

    def test_unregistered_profile(self):
        self.assertEqual(
            audit_registry({"version": 1, "resources": []}, INVENTORY)["findings"][0]["finding"], "unregistered_profile"
        )

    def test_duplicate_and_untrusted_claims(self):
        for candidate in (
            {"version": True, "resources": []},
            {"version": 1, "resources": [*LEDGER["resources"], *LEDGER["resources"]]},
            {"version": 1, "resources": [{**LEDGER["resources"][0], "owner": "external"}]},
            {"version": 1, "resources": [{**LEDGER["resources"][0], "identifier": "../bad name"}]},
        ):
            with self.subTest(candidate=candidate), self.assertRaises(RegistryError):
                validate_registry(candidate)

    def test_no_mutation(self):
        before = copy.deepcopy(LEDGER)
        audit_registry(LEDGER, INVENTORY)
        self.assertEqual(LEDGER, before)


if __name__ == "__main__":
    unittest.main()
