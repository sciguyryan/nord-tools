"""Multiple-profile restoration acceptance using the existing lifecycle executor."""

import json
from copy import deepcopy

from test_restore_executor import RestoreTestBase


class MultipleProfileRestorationTests(RestoreTestBase):
    def setUp(self):
        super().setUp()
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["vpn_profiles"]["secondary"] = {
            "selection": {"mode": "pinned", "server": "uk716"},
            "sharing": "isolated",
        }
        self.policy_path.write_text(json.dumps(policy), encoding="utf-8")
        secondary = deepcopy(self.config["tunnels"]["primary"])
        secondary["endpoint_address"] = "198.51.100.11"
        secondary["tunnel_address"] = "10.213.241.2/32"
        secondary["underlay"] = {
            "namespace_address": "10.214.1.2/30",
            "host_address": "10.214.1.1/30",
        }
        self.config["tunnels"]["secondary"] = secondary
        self.config["credentials"]["secondary"] = str(self.credential_path)

    def test_independent_profiles_have_distinct_owned_resources(self):
        report = self.restore()
        self.assertEqual(report["restored"], ["primary", "secondary"])
        self.assertTrue(report["reconciled"])
        allocations = self.load("lifecycle.json")["allocations"]["resources"]
        self.assertEqual(len(allocations), 8)
        self.assertEqual({item["profile"] for item in allocations}, {"primary", "secondary"})
        self.assertEqual(len({item["identifier"] for item in allocations}), 8)
        self.assertEqual(len({item["allocation_id"] for item in allocations}), 8)
        self.assertEqual(len(self.harness.namespaces), 2)
        self.assertEqual(len(self.harness.host_links), 2)
        self.assertEqual(len(self.harness.tunnels), 2)
        self.assertEqual(len(self.load("owner-bindings.json")["bindings"]), 8)

    def test_repeat_run_preserves_both_profiles(self):
        self.restore()
        before = self.load("lifecycle.json")
        result = self.restore(boot_id="00000000-0000-0000-0000-000000000002")
        self.assertEqual(result["restored"], [])
        self.assertFalse(result["network_changes_applied"])
        self.assertTrue(result["reconciled"])
        self.assertEqual(self.load("lifecycle.json"), before)

    def test_unplanned_secondary_is_reported_without_affecting_primary(self):
        del self.config["tunnels"]["secondary"]
        del self.config["credentials"]["secondary"]
        result = self.restore()
        self.assertEqual(result["restored"], ["primary"])
        self.assertEqual(len(self.harness.namespaces), 1)
        self.assertEqual(result["profiles_not_restored"][0]["profile"], "secondary")
