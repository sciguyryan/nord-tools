"""Dependency ordering and conservative offline planning regression tests."""

import unittest

from nord_tools_internal.nordvpn_dependency_plan import plan_dependencies
from nord_tools_internal.nordvpn_reconcile import ReconciliationError


def policy(*names):
    return {
        "version": 1,
        "defaults": {"vpn": names[0]},
        "vpn_profiles": {name: {"selection": {"mode": "country", "country": "GB"}} for name in names},
        "applications": {},
    }


def record(owner="nord-tools", country="GB"):
    return {
        "owner": owner,
        "state": "ready",
        "configuration": {"selection": {"mode": "country", "country": country}, "sharing": "shared"},
    }


def inventory(**profiles):
    return {"version": 1, "profiles": profiles}


def graph(**deps):
    return {"version": 1, "dependencies": deps}


class DependencyPlanTests(unittest.TestCase):
    def test_create_prerequisite_first(self):
        result = plan_dependencies(policy("main", "discord"), inventory(), graph(main=[], discord=["main"]))
        self.assertEqual(
            [(x["profile"], x["action"]) for x in result["operations"]], [("main", "create"), ("discord", "create")]
        )
        self.assertFalse(result["safe_to_execute"])

    def test_retire_dependents_first(self):
        result = plan_dependencies(
            policy("main"),
            inventory(main=record(), old=record(), older=record()),
            graph(main=[], old=["older"], older=[]),
        )
        self.assertEqual([x["profile"] for x in result["operations"]], ["main", "old", "older"])

    def test_blocked_prerequisite_propagates(self):
        result = plan_dependencies(
            policy("main", "discord"), inventory(main=record(owner="external")), graph(main=[], discord=["main"])
        )
        self.assertEqual([x["action"] for x in result["operations"]], ["blocked", "blocked"])
        self.assertTrue(result["blocked"])

    def test_unchanged_unrelated_profile(self):
        result = plan_dependencies(
            policy("main", "discord"),
            inventory(main=record(), discord=record(country="IE")),
            graph(main=[], discord=[]),
        )
        self.assertEqual([x["action"] for x in result["operations"]], ["replace", "unchanged"])

    def test_reject_invalid_graphs(self):
        bad = [
            graph(main=["discord"], discord=["main"]),
            graph(main=[]),
            graph(main=["main"], discord=[]),
            graph(main=["ghost"], discord=[]),
            graph(main=["discord", "discord"], discord=[]),
            {"version": True, "dependencies": {"main": [], "discord": []}},
        ]
        for candidate in bad:
            with self.subTest(candidate=candidate), self.assertRaises(ReconciliationError):
                plan_dependencies(policy("main", "discord"), inventory(), candidate)

    def test_reject_retired_prerequisite(self):
        with self.assertRaises(ReconciliationError):
            plan_dependencies(policy("main"), inventory(old=record()), graph(main=["old"], old=[]))

    def test_deterministic_and_non_mutating(self):
        observed = inventory()
        edges = graph(main=[], discord=["main"])
        first = plan_dependencies(policy("main", "discord"), observed, edges)
        self.assertEqual(first, plan_dependencies(policy("main", "discord"), observed, edges))
        self.assertEqual(observed, inventory())
        self.assertEqual(edges, graph(main=[], discord=["main"]))


class DependencyCommandTests(unittest.TestCase):
    def test_cli_uses_saved_policy_without_mutation(self):
        import contextlib
        import io
        import json
        import os
        from pathlib import Path
        import tempfile
        from unittest.mock import patch

        import nord_tools

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_file = root / "policy.json"
            inventory_file = root / "inventory.json"
            graph_file = root / "graph.json"
            policy_file.write_text(json.dumps(policy("main", "discord")), encoding="utf-8")
            inventory_file.write_text(json.dumps(inventory()), encoding="utf-8")
            graph_file.write_text(json.dumps(graph(main=[], discord=["main"])), encoding="utf-8")
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(root)}):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(nord_tools.main(["manage", "configure", "--policy", str(policy_file)]), 0)
                saved = (root / "nord-tools" / "desired-policy.json").read_bytes()
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(
                        nord_tools.main(
                            [
                                "manage",
                                "dependency-plan",
                                "--inventory",
                                str(inventory_file),
                                "--graph",
                                str(graph_file),
                            ]
                        ),
                        0,
                    )
                result = json.loads(output.getvalue())
                self.assertEqual([item["profile"] for item in result["operations"]], ["main", "discord"])
                self.assertFalse(result["safe_to_execute"])
                self.assertEqual(saved, (root / "nord-tools" / "desired-policy.json").read_bytes())
