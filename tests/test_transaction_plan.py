"""Offline transaction safety contract tests."""

import unittest

from nordvpn_reconcile import ReconciliationError
from nordvpn_transaction_plan import plan_transactions


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


def plan(observed=None, deps=None):
    return plan_transactions(
        policy("main", "discord"),
        {"version": 1, "profiles": observed or {}},
        {"version": 1, "dependencies": deps or {"main": [], "discord": ["main"]}},
    )


class TransactionPlanTests(unittest.TestCase):
    def test_create_is_gated_and_never_executable(self):
        result = plan()
        self.assertFalse(result["safe_to_execute"])
        self.assertFalse(result["network_changes_applied"])
        self.assertFalse(result["ownership_verified"])
        self.assertEqual([x["profile"] for x in result["operations"]], ["main", "discord"])
        self.assertIn("install_fail_closed_protection", result["operations"][0]["stages"])
        self.assertIn("durable_operation_journal", result["operations"][0]["requires"])

    def test_replacement_prepares_before_switch_and_retirement(self):
        result = plan({"main": record(country="IE"), "discord": record()})
        replacement = result["operations"][0]
        self.assertEqual(replacement["action"], "replace")
        self.assertLess(
            replacement["stages"].index("verify_replacement_tunnel_and_dns"),
            replacement["stages"].index("switch_assignment_atomically"),
        )
        self.assertLess(
            replacement["stages"].index("switch_assignment_atomically"),
            replacement["stages"].index("retire_verified_old_resources"),
        )
        self.assertEqual(result["operations"][1]["stages"], [])

    def test_external_conflict_blocks_dependents(self):
        result = plan({"main": record(owner="external")})
        self.assertTrue(result["blocked"])
        self.assertEqual([x["action"] for x in result["operations"]], ["blocked", "blocked"])
        self.assertTrue(all(not x["stages"] for x in result["operations"]))

    def test_invalid_graph_rejected(self):
        with self.assertRaises(ReconciliationError):
            plan(deps={"main": ["discord"], "discord": ["main"]})

    def test_deterministic(self):
        self.assertEqual(plan(), plan())

    def test_cli_read_only(self):
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
            for name, data in (
                ("policy", policy("main", "discord")),
                ("inventory", {"version": 1, "profiles": {}}),
                ("graph", {"version": 1, "dependencies": {"main": [], "discord": ["main"]}}),
            ):
                (root / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(root)}):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(nord_tools.main(["manage", "configure", "--policy", str(root / "policy.json")]), 0)
                saved = (root / "nord-tools" / "desired-policy.json").read_bytes()
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(
                        nord_tools.main(
                            [
                                "manage",
                                "transaction-plan",
                                "--inventory",
                                str(root / "inventory.json"),
                                "--graph",
                                str(root / "graph.json"),
                            ]
                        ),
                        0,
                    )
                self.assertFalse(json.loads(output.getvalue())["safe_to_execute"])
                self.assertEqual(saved, (root / "nord-tools" / "desired-policy.json").read_bytes())
