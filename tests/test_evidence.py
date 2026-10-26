"""Read-only evidence correlation never grants ownership authority."""

import unittest
from unittest.mock import patch

from nordvpn_evidence import correlate
from nordvpn_manage import main
from nordvpn_registry import RegistryError


OBSERVATION = {
    "mode": "live_read_only",
    "network_changes_applied": False,
    "namespaces": ["nt-app"],
    "host_interfaces": [{"name": "wg0"}],
    "namespace_details": [{"name": "nt-app", "interfaces": [{"name": "wg0"}]}],
}


def ledger(kind, identifier):
    return {
        "version": 1,
        "resources": [{"kind": kind, "identifier": identifier, "profile": "main", "owner": "nord-tools"}],
    }


class EvidenceTests(unittest.TestCase):
    def test_namespace_name_match_is_not_ownership(self):
        result = correlate(ledger("namespace", "nt-app"), OBSERVATION)
        self.assertEqual(result["findings"][0]["evidence"], "name_observed")
        self.assertFalse(result["ownership_verified"])
        self.assertFalse(result["safe_to_delete"])

    def test_scoped_interfaces_and_ambiguous_names(self):
        for identifier, expected in (
            ("host:wg0", "name_observed"),
            ("nt-app:wg0", "name_observed"),
            ("host:missing", "name_missing"),
            ("wg0", "ambiguous_or_unknown_scope"),
            ("unknown:wg0", "ambiguous_or_unknown_scope"),
        ):
            with self.subTest(identifier=identifier):
                self.assertEqual(
                    correlate(ledger("interface", identifier), OBSERVATION)["findings"][0]["evidence"], expected
                )

    def test_unsupported_kind(self):
        self.assertEqual(
            correlate(ledger("firewall", "table1"), OBSERVATION)["findings"][0]["evidence"], "unsupported_evidence_kind"
        )

    def test_reject_incomplete_and_untrusted_discovery(self):
        for change in (
            {"mode": "fixture"},
            {"network_changes_applied": True},
            {"namespace_details": []},
            {"host_interfaces": [{"name": "wg0"}, {"name": "wg0"}]},
        ):
            with self.subTest(change=change), self.assertRaises(RegistryError):
                correlate(ledger("namespace", "nt-app"), {**OBSERVATION, **change})

    def test_command_dispatch_without_saved_policy(self):
        with (
            patch("nordvpn_manage.read_json", return_value=ledger("namespace", "nt-app")),
            patch("nordvpn_manage.discover", return_value=OBSERVATION),
            patch("builtins.print") as printer,
        ):
            self.assertEqual(main(["evidence", "--registry", "unused.json"]), 0)
            self.assertIn('"safe_to_delete": false', printer.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
