"""Allocation correlation must never grant ownership or cleanup authority."""

import unittest
from unittest.mock import patch

from nord_tools_internal.nordvpn_identity_evidence import inspect_identity_evidence
from nordvpn_manage import main
from nord_tools_internal.nordvpn_registry import RegistryError


TOKEN = "a" * 32


def ledger(kind="namespace", identifier="managed"):
    return {
        "version": 2,
        "resources": [
            {
                "kind": kind,
                "identifier": identifier,
                "profile": "default",
                "owner": "nord-tools",
                "allocation_id": TOKEN,
            }
        ],
    }


def observation(names=None):
    names = ["managed"] if names is None else names
    return {
        "mode": "live_read_only",
        "network_changes_applied": False,
        "namespaces": names,
        "host_interfaces": [],
        "namespace_details": [{"name": name, "interfaces": []} for name in names],
    }


class IdentityEvidenceTests(unittest.TestCase):
    def test_matching_name_is_not_ownership(self):
        result = inspect_identity_evidence(ledger(), observation())
        self.assertEqual(result["findings"][0]["classification"], "unverified_name_match")
        self.assertEqual(result["findings"][0]["allocation_id"], TOKEN)
        self.assertFalse(result["ownership_verified"])
        self.assertFalse(result["safe_to_modify"])
        self.assertFalse(result["safe_to_delete"])
        self.assertFalse(result["findings"][0]["allocation_binding_verified"])

    def test_missing_name_is_stale_or_not_created(self):
        self.assertEqual(
            inspect_identity_evidence(ledger(), observation([]))["findings"][0]["classification"],
            "stale_or_unprovisioned",
        )

    def test_ambiguous_interface(self):
        self.assertEqual(
            inspect_identity_evidence(ledger("interface", "eth0"), observation())["findings"][0]["classification"],
            "unverifiable_scope",
        )

    def test_unsupported_kind(self):
        self.assertEqual(
            inspect_identity_evidence(ledger("route", "10.0.0.0/8"), observation())["findings"][0]["classification"],
            "unsupported_evidence",
        )

    def test_incomplete_observation_rejected(self):
        with self.assertRaises(RegistryError):
            inspect_identity_evidence(ledger(), {"mode": "live_read_only"})

    def test_invalid_allocation_rejected(self):
        invalid = ledger()
        invalid["resources"][0]["allocation_id"] = "bad"
        with self.assertRaises(RegistryError):
            inspect_identity_evidence(invalid, observation())

    def test_dispatch_is_read_only(self):
        with (
            patch("nordvpn_manage.read_json", return_value=ledger()),
            patch("nordvpn_manage.discover", return_value=observation()) as discovery,
            patch("builtins.print") as printer,
        ):
            self.assertEqual(main(["identity-evidence", "--registry", "allocations.json"]), 0)
        discovery.assert_called_once_with()
        self.assertIn('"safe_to_delete": false', printer.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
