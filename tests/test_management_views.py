"""Deterministic and non-executable management view regressions."""

import unittest

from nordvpn_management_views import cleanup_plan, topology_graph
from nordvpn_reconcile import ReconciliationError


POLICY = {
    "version": 1,
    "defaults": {"vpn": "main"},
    "vpn_profiles": {
        "main": {"sharing": "shared", "selection": {"mode": "country", "country": "AD"}},
        "uk": {"sharing": "shared", "selection": {"mode": "country", "country": "GB"}},
        "private": {"sharing": "isolated", "selection": {"mode": "country", "country": "IE"}},
    },
    "applications": {
        "discord": {"vpn": "uk", "executable": "/usr/bin/discord"},
        "browser": {"vpn": "uk", "executable": "/usr/bin/browser"},
        "signal": {"vpn": "private", "executable": "/usr/bin/signal"},
    },
}


class ManagementViewsTests(unittest.TestCase):
    def test_unicode_shared_and_isolated(self):
        graph = topology_graph(POLICY)
        self.assertIn("├── [main: shared]", graph)
        self.assertIn("[uk: shared]", graph)
        self.assertIn("[private: isolated]", graph)
        self.assertIn("browser", graph)
        self.assertIn("discord", graph)
        self.assertIn("other applications (inherited)", graph)
        self.assertIn("NOT live networking", graph)
        self.assertEqual(graph, topology_graph(POLICY))

    def test_ascii_and_transient(self):
        graph = topology_graph(POLICY, ascii_only=True, scope="transient")
        self.assertTrue(graph.startswith("[root] (configured transient"))
        self.assertIn("+-- [main", graph)
        self.assertNotIn("├", graph)

    def test_unassigned_profile(self):
        policy = {**POLICY, "applications": {}}
        self.assertIn("(no assigned applications)", topology_graph(policy))

    def test_cleanup_excludes_external_and_is_never_executable(self):
        inventory = {
            "version": 1,
            "profiles": {
                "managed": {
                    "owner": "nord-tools",
                    "state": "degraded",
                    "configuration": POLICY["vpn_profiles"]["main"],
                },
                "external": {"owner": "external", "state": "ready", "configuration": POLICY["vpn_profiles"]["uk"]},
            },
        }
        plan = cleanup_plan(inventory)
        self.assertEqual([entry["profile"] for entry in plan["candidates"]], ["managed"])
        self.assertEqual(plan["excluded_external_profiles"], ["external"])
        self.assertFalse(plan["safe_to_execute"])
        self.assertFalse(plan["network_changes_applied"])

    def test_empty_cleanup(self):
        self.assertEqual(cleanup_plan({"version": 1, "profiles": {}})["candidates"], [])

    def test_invalid_cleanup_fails(self):
        with self.assertRaises(ReconciliationError):
            cleanup_plan({"version": 1, "profiles": {"bad": {"owner": "nord-tools"}}})


if __name__ == "__main__":
    unittest.main()


class ManagementCommandTests(unittest.TestCase):
    def test_graph_and_cleanup_dispatch(self):
        import contextlib
        import io
        import json
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from nordvpn_manage import main

        with tempfile.TemporaryDirectory() as directory:
            policy_file = Path(directory) / "policy.json"
            inventory_file = Path(directory) / "inventory.json"
            policy_file.write_text(json.dumps(POLICY), encoding="utf-8")
            inventory_file.write_text(json.dumps({"version": 1, "profiles": {}}), encoding="utf-8")
            output = io.StringIO()
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}), contextlib.redirect_stdout(output):
                self.assertEqual(main(["configure", "--policy", str(policy_file)]), 0)
                output.seek(0)
                output.truncate()
                self.assertEqual(main(["graph", "--ascii"]), 0)
                self.assertIn("configured persistent", output.getvalue())
                output.seek(0)
                output.truncate()
                self.assertEqual(main(["cleanup-plan", "--inventory", str(inventory_file)]), 0)
                self.assertFalse(json.loads(output.getvalue())["safe_to_execute"])
