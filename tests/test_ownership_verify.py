"""Adversarial tests for ownership verification preflight and its owner-record store."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nord_tools_internal.nordvpn_identity import allocate_identity
from nord_tools_internal.nordvpn_lifecycle import record_transition
from nord_tools_internal.nordvpn_ownership_verify import (
    initialise_bindings,
    preflight_ownership,
    read_bindings,
    record_binding,
)
from nord_tools_internal.nordvpn_registry import RegistryError


def observation(namespaces=("nt-managed",), host=(), details=None):
    """Build a complete discovery-shaped snapshot for offline classification."""
    entries = details
    if entries is None:
        entries = [{"name": name, "interfaces": []} for name in namespaces]
    return {
        "mode": "live_read_only",
        "network_changes_applied": False,
        "namespaces": list(namespaces),
        "host_interfaces": list(host),
        "namespace_details": entries,
    }


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "owner-bindings.json"
        self.resource = allocate_identity("namespace", "nt-managed", "test")
        self.journal = {"version": 1, "allocations": {"version": 2, "resources": [self.resource]}, "events": []}

    def test_initialise_is_exclusive(self):
        empty = initialise_bindings(self.store)
        self.assertEqual(empty, {"version": 1, "bindings": []})
        with self.assertRaises(RegistryError):
            initialise_bindings(self.store)

    def test_record_and_read_roundtrip(self):
        initialise_bindings(self.store)
        token = self.resource["allocation_id"]
        record_binding(self.store, self.journal, token, {"device": 5, "inode": 9})
        stored = read_bindings(self.store, self.journal)
        self.assertEqual(stored["bindings"][0]["binding"], {"device": 5, "inode": 9})

    def test_bound_identity_comes_from_the_validated_ledger(self):
        initialise_bindings(self.store)
        token = self.resource["allocation_id"]
        revised = record_binding(self.store, self.journal, token, {"device": 5, "inode": 9})
        self.assertEqual(revised["bindings"][0]["identifier"], "nt-managed")
        self.assertEqual(revised["bindings"][0]["kind"], "namespace")

    def test_rebinding_is_refused_and_records_stay_immutable(self):
        initialise_bindings(self.store)
        token = self.resource["allocation_id"]
        record_binding(self.store, self.journal, token, {"device": 5, "inode": 9})
        with self.assertRaises(RegistryError):
            record_binding(self.store, self.journal, token, {"device": 5, "inode": 10})
        self.assertEqual(len(read_bindings(self.store, self.journal)["bindings"]), 1)

    def test_binding_without_allocation_is_refused(self):
        initialise_bindings(self.store)
        with self.assertRaises(RegistryError):
            record_binding(self.store, self.journal, "f" * 32, {"device": 5, "inode": 9})

    def test_binding_shape_must_match_resource_kind(self):
        initialise_bindings(self.store)
        with self.assertRaises(RegistryError):
            record_binding(self.store, self.journal, self.resource["allocation_id"], {"scope": "host", "ifindex": 3})

    def test_missing_store_is_refused(self):
        with self.assertRaises(RegistryError):
            read_bindings(self.store, self.journal)

    def test_symlinked_store_is_refused(self):
        target = self.root / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        self.store.symlink_to(target)
        with self.assertRaises(RegistryError):
            read_bindings(self.store, self.journal)

    def test_group_writable_store_is_refused(self):
        initialise_bindings(self.store)
        os.chmod(self.store, 0o640)
        with self.assertRaises(RegistryError):
            read_bindings(self.store, self.journal)

    def test_structurally_invalid_documents_are_refused(self):
        initialise_bindings(self.store)
        for invalid in (
            {"version": 2, "bindings": []},
            {"version": 1},
            {"version": 1, "bindings": {}},
            {"version": 1, "bindings": ["not-an-object"]},
        ):
            with self.subTest(invalid=invalid):
                self.store.write_text(json.dumps(invalid), encoding="utf-8")
                with self.assertRaises(RegistryError):
                    read_bindings(self.store, self.journal)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.resource = allocate_identity("namespace", "nt-managed", "test")
        self.token = self.resource["allocation_id"]
        self.journal = {"version": 1, "allocations": {"version": 2, "resources": [self.resource]}, "events": []}
        self.bindings = {
            "version": 1,
            "bindings": [
                {
                    "allocation_id": self.token,
                    "kind": "namespace",
                    "identifier": "nt-managed",
                    "binding": {"device": 5, "inode": 9},
                },
            ],
        }
        self.identities = {"nt-managed": {"device": 5, "inode": 9}}

    def advance(self, *states):
        journal = self.journal
        for state in states:
            journal = record_transition(journal, self.token, state)
        self.journal = journal

    def active_journal(self):
        self.advance("reserved", "creating", "active")

    def result(self, bindings=None, journal=None, observation_data=None, **kwargs):
        return preflight_ownership(
            self.journal if journal is None else journal,
            self.bindings if bindings is None else bindings,
            observation() if observation_data is None else observation_data,
            netns_identity=self.identities,
            **kwargs,
        )

    def test_verified_binding_classifies_current(self):
        self.active_journal()
        result = self.result()
        finding = result["resources"][0]
        self.assertEqual(finding["finding"], "verified_current")
        self.assertTrue(finding["verified"])
        self.assertEqual(finding["observed_identity"], {"device": 5, "inode": 9})
        self.assertTrue(result["ownership_verified"])
        self.assertFalse(result["operator_review_required"])
        self.assertEqual(result["verified_resources"], [self.token])

    def test_verification_never_relinquishes_execution_authority(self):
        self.active_journal()
        result = self.result()
        self.assertFalse(result["safe_to_modify"])
        self.assertFalse(result["safe_to_delete"])
        self.assertFalse(result["automatic_recovery_permitted"])
        self.assertTrue(result["requires_reverification_at_execution"])

    def test_name_match_without_record_is_never_ownership(self):
        result = self.result(bindings={"version": 1, "bindings": []})
        self.assertEqual(result["resources"][0]["finding"], "unbound_claim")
        self.assertFalse(result["resources"][0]["verified"])
        self.assertFalse(result["ownership_verified"])

    def test_identity_conflict_is_rejected(self):
        self.active_journal()
        self.identities["nt-managed"] = {"device": 5, "inode": 10}
        result = self.result()
        self.assertEqual(result["resources"][0]["finding"], "identity_conflict")
        self.assertFalse(result["ownership_verified"])

    def test_missing_resource_fails_closed(self):
        self.active_journal()
        result = self.result(observation_data=observation([]))
        self.assertEqual(result["resources"][0]["finding"], "resource_missing")
        self.assertFalse(result["ownership_verified"])

    def test_recorded_retirement_with_absent_resource_is_consistent(self):
        self.advance("reserved", "creating", "active", "retiring", "retired")
        result = self.result(observation_data=observation([]))
        finding = result["resources"][0]
        self.assertEqual(finding["finding"], "consistent_retired")
        self.assertTrue(finding["verified"])
        self.assertTrue(result["ownership_verified"])

    def test_observed_name_after_recorded_retirement_is_reuse(self):
        self.advance("reserved", "creating", "active", "retiring", "retired")
        result = self.result()
        self.assertEqual(result["resources"][0]["finding"], "possible_name_reuse")
        self.assertFalse(result["ownership_verified"])

    def test_interrupted_lifecycle_state_blocks_verification_with_matching_identity(self):
        self.advance("reserved", "creating")
        result = self.result()
        self.assertEqual(result["resources"][0]["finding"], "interrupted_transition")
        self.assertFalse(result["ownership_verified"])

    def test_unresolved_intent_blocks_verification_before_anything_else(self):
        self.advance("reserved", "creating", "active", "retiring")
        intents = {
            "version": 1,
            "operations": [
                {
                    "operation_id": "b" * 32,
                    "allocation_id": self.token,
                    "action": "retire",
                    "outcome": "pending",
                    "journal_sequence": 4,
                },
            ],
        }
        result = preflight_ownership(
            self.journal, self.bindings, observation(), intents, netns_identity=self.identities
        )
        self.assertEqual(result["resources"][0]["finding"], "uncertain_intent")
        self.assertFalse(result["resources"][0]["verified"])
        self.assertEqual(result["unresolved_intents"][0]["operation_id"], "b" * 32)
        self.assertFalse(result["ownership_verified"])

    def test_unsupported_resource_kind_fails_the_batch(self):
        route = allocate_identity("route", "10.0.0.0/8", "test")
        self.journal = {
            "version": 1,
            "allocations": {"version": 2, "resources": [self.resource, route]},
            "events": [],
        }
        result = self.result()
        self.assertEqual(result["resources"][1]["finding"], "unsupported_resource_kind")
        self.assertFalse(result["resources"][1]["verified"])
        self.assertFalse(result["ownership_verified"])

    def test_one_uncertain_resource_fails_the_complete_batch(self):
        other = allocate_identity("interface", "eth0", "test")
        journal = {
            "version": 1,
            "allocations": {"version": 2, "resources": [self.resource, other]},
            "events": [],
        }
        journal = record_transition(journal, self.token, "reserved")
        journal = record_transition(journal, self.token, "creating")
        journal = record_transition(journal, self.token, "active")
        bindings = {
            "version": 1,
            "bindings": [
                {
                    "allocation_id": self.token,
                    "kind": "namespace",
                    "identifier": "nt-managed",
                    "binding": {"device": 5, "inode": 9},
                },
                {
                    "allocation_id": other["allocation_id"],
                    "kind": "interface",
                    "identifier": "eth0",
                    "binding": {"scope": "nt-managed", "ifindex": 424242},
                },
            ],
        }
        detailed = [{"name": "nt-managed", "interfaces": [{"name": "eth0", "index": 7}]}]
        result = preflight_ownership(
            journal,
            bindings,
            observation(details=detailed),
            netns_identity={"nt-managed": {"device": 5, "inode": 9}},
        )
        findings = {item["identifier"]: item for item in result["resources"]}
        self.assertEqual(findings["nt-managed"]["finding"], "verified_current")
        self.assertEqual(findings["eth0"]["finding"], "identity_conflict")
        self.assertFalse(result["ownership_verified"])
        self.assertTrue(result["operator_review_required"])


class InterfaceBindingTests(unittest.TestCase):
    def setUp(self):
        self.resource = allocate_identity("interface", "eth0", "test")
        self.token = self.resource["allocation_id"]
        self.journal = {"version": 1, "allocations": {"version": 2, "resources": [self.resource]}, "events": []}
        self.journal = record_transition(self.journal, self.token, "reserved")
        self.journal = record_transition(self.journal, self.token, "creating")
        self.journal = record_transition(self.journal, self.token, "active")
        self.bindings = {
            "version": 1,
            "bindings": [
                {
                    "allocation_id": self.token,
                    "kind": "interface",
                    "identifier": "eth0",
                    "binding": {"scope": "nt-managed", "ifindex": 7},
                },
            ],
        }

    def snapshot(self, interfaces):
        return observation(details=[{"name": "nt-managed", "interfaces": list(interfaces)}])

    def test_matching_interface_binding_verifies(self):
        result = preflight_ownership(self.journal, self.bindings, self.snapshot([{"name": "eth0", "index": 7}]))
        finding = result["resources"][0]
        self.assertEqual(finding["finding"], "verified_current")
        self.assertTrue(result["ownership_verified"])

    def test_changed_interface_index_is_identity_conflict(self):
        result = preflight_ownership(self.journal, self.bindings, self.snapshot([{"name": "eth0", "index": 8}]))
        self.assertEqual(result["resources"][0]["finding"], "identity_conflict")
        self.assertFalse(result["ownership_verified"])

    def test_absent_interface_means_missing_resource(self):
        result = preflight_ownership(self.journal, self.bindings, self.snapshot([]))
        self.assertEqual(result["resources"][0]["finding"], "resource_missing")
        self.assertFalse(result["ownership_verified"])

    def test_unknown_scope_is_reported_not_guessed(self):
        # The claimed namespace is absent from an otherwise complete snapshot.
        observed = observation(namespaces=("other",), details=[{"name": "other", "interfaces": []}])
        result = preflight_ownership(self.journal, self.bindings, observed)
        self.assertEqual(result["resources"][0]["finding"], "scope_missing")
        self.assertFalse(result["ownership_verified"])


class NetnsEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.resource = allocate_identity("namespace", "nt-managed", "test")
        self.token = self.resource["allocation_id"]
        self.journal = {"version": 1, "allocations": {"version": 2, "resources": [self.resource]}, "events": []}
        self.bindings = {
            "version": 1,
            "bindings": [
                {
                    "allocation_id": self.token,
                    "kind": "namespace",
                    "identifier": "nt-managed",
                    "binding": {"device": 5, "inode": 9},
                },
            ],
        }

    def test_incomplete_identity_evidence_is_refused(self):
        with self.assertRaises(RegistryError):
            preflight_ownership(self.journal, self.bindings, observation(), netns_identity={})

    def test_identity_evidence_for_unobserved_namespace_is_refused(self):
        with self.assertRaises(RegistryError):
            preflight_ownership(
                self.journal,
                self.bindings,
                observation(),
                netns_identity={"nt-unrelated": {"device": 1, "inode": 2}},
            )

    def test_absent_claimed_namespace_needs_no_identity_evidence(self):
        result = preflight_ownership(self.journal, self.bindings, observation([]), netns_identity={})
        self.assertEqual(result["resources"][0]["finding"], "resource_missing")


class DiscoveryValidationTests(unittest.TestCase):
    def setUp(self):
        self.resource = allocate_identity("namespace", "nt-managed", "test")
        self.journal = {"version": 1, "allocations": {"version": 2, "resources": [self.resource]}, "events": []}

    def test_incomplete_observation_is_refused_wholesale(self):
        for bad in ({"mode": "live_read_only"}, {"mode": "wrong", "network_changes_applied": False}):
            with self.subTest(bad=bad), self.assertRaises(RegistryError):
                preflight_ownership(self.journal, {"version": 1, "bindings": []}, bad)

    def test_duplicated_interfaces_are_refused(self):
        observed = observation(host=[{"name": "wlan0", "index": 3}, {"name": "wlan0", "index": 3}])
        with self.assertRaises(RegistryError):
            preflight_ownership(self.journal, {"version": 1, "bindings": []}, observed)

    def test_invalid_journal_or_bindings_are_refused(self):
        with self.assertRaises(RegistryError):
            preflight_ownership({}, {"version": 1, "bindings": []}, observation())
        with self.assertRaises(RegistryError):
            preflight_ownership(self.journal, {"version": 2, "bindings": []}, observation())

    def test_unclaimed_observations_are_listed_without_ownership_claims(self):
        detailed = [
            {"name": "nt-managed", "interfaces": []},
            {"name": "other", "interfaces": []},
        ]
        observed = observation(
            namespaces=["nt-managed", "other"], host=[{"name": "wlan0", "index": 4}], details=detailed
        )
        result = preflight_ownership(self.journal, {"version": 1, "bindings": []}, observed)
        self.assertIn({"kind": "namespace", "identifier": "other"}, result["unclaimed"])
        self.assertIn({"kind": "interface", "scope": "host", "identifier": "wlan0"}, result["unclaimed"])
        # Unclaimed observations must not influence the claimed-resource batch.
        self.assertFalse(result["ownership_verified"])


class CliTests(unittest.TestCase):
    def setUp(self):
        from nordvpn_manage import main

        self.main = main
        self.journal = {
            "version": 1,
            "allocations": {
                "version": 2,
                "resources": [
                    {
                        "kind": "namespace",
                        "identifier": "nt-managed",
                        "profile": "test",
                        "owner": "nord-tools",
                        "allocation_id": "a" * 32,
                    },
                ],
            },
            "events": [],
        }
        self.bindings = {"version": 1, "bindings": []}

    def test_dispatch_is_read_only(self):
        output = io.StringIO()
        with (
            patch("nordvpn_manage.read_json", side_effect=[self.journal, self.bindings]),
            patch("nordvpn_manage.discover", return_value=observation()) as discovery,
            contextlib.redirect_stdout(output),
        ):
            code = self.main(["ownership-preflight", "--journal", "j.json", "--bindings", "b.json"])
        self.assertEqual(code, 0)
        discovery.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertFalse(result["safe_to_delete"])
        self.assertEqual(result["resources"][0]["finding"], "unbound_claim")

    def test_dispatch_accepts_optional_intents(self):
        journal = record_transition(self.journal, "a" * 32, "reserved")
        journal = record_transition(journal, "a" * 32, "creating")
        # A create intent must reference the "creating" transition (sequence 2).
        pending = {
            "version": 1,
            "operations": [
                {
                    "operation_id": "b" * 32,
                    "allocation_id": "a" * 32,
                    "action": "create",
                    "outcome": "uncertain",
                    "journal_sequence": 2,
                },
            ],
        }
        output = io.StringIO()
        with (
            patch("nordvpn_manage.read_json", side_effect=[journal, self.bindings, pending]),
            patch("nordvpn_manage.discover", return_value=observation()),
            contextlib.redirect_stdout(output),
        ):
            code = self.main(
                [
                    "ownership-preflight",
                    "--journal",
                    "j.json",
                    "--bindings",
                    "b.json",
                    "--intents",
                    "i.json",
                ]
            )
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["resources"][0]["finding"], "uncertain_intent")
        self.assertFalse(result["ownership_verified"])

    def test_failed_discovery_fails_closed(self):
        from nord_tools_internal.nordvpn_discovery import DiscoveryError

        stderr = io.StringIO()
        with (
            patch("nordvpn_manage.read_json", side_effect=[self.journal, self.bindings]),
            patch("nordvpn_manage.discover", side_effect=DiscoveryError("unavailable")),
            contextlib.redirect_stderr(stderr),
        ):
            code = self.main(["ownership-preflight", "--journal", "j.json", "--bindings", "b.json"])
        self.assertEqual(code, 2)
        self.assertIn("unavailable", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
