"""Fail-closed tests for live-name correlation without ownership authority."""

import unittest

from nord_tools_internal.nordvpn_lifecycle import record_transition
from nord_tools_internal.nordvpn_lifecycle_evidence import inspect_live_lifecycle
from nord_tools_internal.nordvpn_registry import RegistryError


class LiveLifecycleEvidenceTests(unittest.TestCase):
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
                    },
                ],
            },
            "events": [],
        }
        self.observed = {
            "mode": "live_read_only",
            "network_changes_applied": False,
            "namespaces": ["ns1"],
            "host_interfaces": [{"name": "nt0", "index": 3}],
            "namespace_details": [{"name": "ns1", "interfaces": [{"name": "wg0", "index": 2}]}],
        }

    def test_matching_name_is_never_authority(self):
        result = inspect_live_lifecycle(self.journal, self.observed)
        self.assertEqual(result["resources"][0]["finding"], "name_observed_unverified")
        self.assertFalse(result["ownership_verified"])
        self.assertFalse(result["safe_to_modify"])
        self.assertFalse(result["safe_to_delete"])

    def test_missing_active_resource_is_possible_stale(self):
        journal = record_transition(
            record_transition(record_transition(self.journal, self.token, "reserved"), self.token, "creating"),
            self.token,
            "active",
        )
        observed = {**self.observed, "host_interfaces": []}
        self.assertEqual(
            inspect_live_lifecycle(journal, observed)["resources"][0]["finding"], "possible_stale_lifecycle"
        )

    def test_retired_name_reuse_is_not_owned(self):
        journal = self.journal
        for state in ("reserved", "creating", "active", "retiring", "retired"):
            journal = record_transition(journal, self.token, state)
        self.assertEqual(
            inspect_live_lifecycle(journal, self.observed)["resources"][0]["finding"], "possible_orphan_or_name_reuse"
        )

    def test_ambiguous_interface_name(self):
        observed = {
            **self.observed,
            "namespace_details": [{"name": "ns1", "interfaces": [{"name": "nt0", "index": 2}]}],
        }
        self.assertEqual(inspect_live_lifecycle(self.journal, observed)["resources"][0]["finding"], "ambiguous_scope")

    def test_rejects_incomplete_and_malicious_observations(self):
        for change in (
            {"mode": "offline"},
            {"network_changes_applied": True},
            {"namespace_details": []},
            {"host_interfaces": [{"name": "nt0"}, {"name": "nt0"}]},
            {"namespaces": ["ns1", "ns1"]},
        ):
            with self.subTest(change=change), self.assertRaises(RegistryError):
                inspect_live_lifecycle(self.journal, {**self.observed, **change})

    def test_namespace_and_unsupported_kinds(self):
        for kind, expected in (("namespace", "name_observed_unverified"), ("route", "unsupported_resource_kind")):
            with self.subTest(kind=kind):
                resource = {**self.journal["allocations"]["resources"][0], "kind": kind, "identifier": "ns1"}
                journal = {**self.journal, "allocations": {"version": 2, "resources": [resource]}}
                self.assertEqual(inspect_live_lifecycle(journal, self.observed)["resources"][0]["finding"], expected)
