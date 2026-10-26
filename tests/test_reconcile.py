"""Offline reconciliation contract and conservative ownership tests."""

import unittest
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

import nord_tools

from nord_tools_internal.nordvpn_reconcile import ReconciliationError, plan_reconciliation


POLICY = {
    "version": 1,
    "defaults": {"vpn": "main"},
    "vpn_profiles": {
        "main": {"selection": {"mode": "country", "country": "GB"}},
        "discord": {"selection": {"mode": "country", "country": "IE"}},
    },
    "applications": {},
}


def record(country, owner="nord-tools", state="ready"):
    return {
        "owner": owner,
        "state": state,
        "configuration": {"selection": {"mode": "country", "country": country}, "sharing": "shared"},
    }


class ReconcileTests(unittest.TestCase):
    def plan(self, records):
        return plan_reconciliation(POLICY, {"version": 1, "profiles": records})

    def test_create_without_touching_existing(self):
        result = self.plan({"main": record("GB")})
        self.assertEqual(
            [(op["profile"], op["action"]) for op in result["operations"]],
            [("discord", "create"), ("main", "unchanged")],
        )
        self.assertFalse(result["network_changes_applied"])

    def test_replace_only_changed_profile(self):
        result = self.plan({"main": record("AD"), "discord": record("IE")})
        self.assertEqual([op["action"] for op in result["operations"]], ["unchanged", "replace"])

    def test_retire_only_owned_extra(self):
        result = self.plan({"main": record("GB"), "discord": record("IE"), "old": record("FR")})
        self.assertEqual(result["operations"][-1]["action"], "retire")

    def test_external_conflict_blocks(self):
        result = self.plan({"main": record("GB", owner="external")})
        self.assertTrue(result["blocked"])
        self.assertEqual(result["operations"][-1]["action"], "blocked")

    def test_external_extra_is_not_retired(self):
        result = self.plan({"other": record("FR", owner="external")})
        self.assertNotIn("other", [op["profile"] for op in result["operations"]])

    def test_missing_and_degraded_are_repaired(self):
        for state in ("missing", "degraded"):
            with self.subTest(state=state):
                self.assertEqual(self.plan({"main": record("GB", state=state)})["operations"][-1]["action"], "repair")

    def test_reject_malformed_and_unrecognised_inventory(self):
        for inventory in (
            {"version": 2, "profiles": {}},
            {"version": 1, "profiles": {"main": {"owner": "unknown", "state": "ready", "configuration": {}}}},
            {"version": 1, "profiles": []},
        ):
            with self.subTest(inventory=inventory), self.assertRaises(ReconciliationError):
                plan_reconciliation(POLICY, inventory)

    def test_cli_reconcile_reads_saved_intent_without_modifying_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            inventory = root / "inventory.json"
            policy.write_text(json.dumps(POLICY), encoding="utf-8")
            inventory.write_text(json.dumps({"version": 1, "profiles": {"main": record("GB")}}), encoding="utf-8")
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(root)}):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(nord_tools.main(["manage", "configure", "--policy", str(policy)]), 0)
                saved = (root / "nord-tools" / "desired-policy.json").read_bytes()
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(nord_tools.main(["manage", "reconcile", "--inventory", str(inventory)]), 0)
                self.assertEqual(json.loads(output.getvalue())["operations"][0]["action"], "create")
                self.assertEqual((root / "nord-tools" / "desired-policy.json").read_bytes(), saved)

    def test_repeatable_and_non_mutating(self):
        inventory = {"version": 1, "profiles": {"main": record("GB")}}
        before = repr(inventory)
        self.assertEqual(plan_reconciliation(POLICY, inventory), plan_reconciliation(POLICY, inventory))
        self.assertEqual(repr(inventory), before)


if __name__ == "__main__":
    unittest.main()
