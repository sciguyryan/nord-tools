"""Allocation IDs do not confer authority over live resources."""

import unittest
from unittest.mock import patch

from nord_tools_internal.nordvpn_identity import allocate_identity, inspect_allocations, validate_allocations
from nordvpn_manage import main
from nord_tools_internal.nordvpn_registry import RegistryError


class IdentityTests(unittest.TestCase):
    def test_allocation_is_unique_and_well_formed(self):
        first = allocate_identity("namespace", "nt-one", "main")
        second = allocate_identity("namespace", "nt-two", "main")
        self.assertNotEqual(first["allocation_id"], second["allocation_id"])
        self.assertEqual(len(first["allocation_id"]), 32)
        self.assertFalse(inspect_allocations({"version": 2, "resources": [first]})["ownership_verified"])

    def test_duplicate_token_and_resource_rejected(self):
        first = allocate_identity("namespace", "nt-one", "main")
        same_token = {**first, "identifier": "nt-two"}
        same_resource = {**first, "allocation_id": "a" * 32}
        for other in (same_token, same_resource):
            with self.subTest(other=other), self.assertRaises(RegistryError):
                validate_allocations({"version": 2, "resources": [first, other]})

    def test_reject_malformed_and_legacy(self):
        entry = allocate_identity("interface", "host:wg0", "main")
        for token in ("", "F" * 32, "0" * 31, None, True):
            with self.subTest(token=token), self.assertRaises(RegistryError):
                validate_allocations({"version": 2, "resources": [{**entry, "allocation_id": token}]})
        with self.assertRaises(RegistryError):
            validate_allocations({"version": 1, "resources": []})

    def test_command_is_read_only(self):
        entry = allocate_identity("namespace", "nt-one", "main")
        with (
            patch("nordvpn_manage.read_json", return_value={"version": 2, "resources": [entry]}),
            patch("builtins.print") as printer,
        ):
            self.assertEqual(main(["identities", "--registry", "unused.json"]), 0)
            self.assertIn('"safe_to_delete": false', printer.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
