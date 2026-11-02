"""Integration seam tests binding the part-7 executors together offline.

These tests exercise the combinations the individual executor suites cannot
reach: a configured transient policy that provably influences nothing, the
recovery-to-restore seam after an injected mid-flight crash, cross-profile
preservation including application bookkeeping, the repeated-run convergence
invariants across cleanup and recovery, and the deadline refusal of transient
scope across every lifecycle command.
"""

import json
import tempfile
import unittest
from unittest.mock import patch

import test_cleanup_executor as cleanup_tests
import test_restore_executor as restore_tests
from nord_tools_internal.nordvpn_provision_execution import ProvisioningUncertainError
from nord_tools_internal.nordvpn_recovery_executor import plan_recovery
from nord_tools_internal.nordvpn_operation_store import initialise_intents, update_intent

APPLICATION_POLICY = {
    "version": 1,
    "defaults": {"vpn": "alpha"},
    "vpn_profiles": {"alpha": dict(cleanup_tests.CONFIG)},
    "applications": {
        "app-a": {"executable": "/usr/bin/app-a", "vpn": "alpha"},
        "app-b": {"executable": "/usr/bin/app-b", "vpn": "alpha"},
    },
}


class RecoveryRestoreSeamTests(restore_tests.RestoreTestBase):
    def half_built_fixture(self):
        """Crash after the namespace binding, before interfaces, mid-boot."""
        from test_recovery_executor import ecosystem as four_token

        journal, bindings, tokens = four_token(
            "primary", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", states="creating"
        )
        bindings = {"version": 1, "bindings": [entry for entry in bindings["bindings"] if entry["kind"] == "namespace"]}
        (self.root / "lifecycle.json").write_text(json.dumps(journal), encoding="utf-8")
        (self.root / "owner-bindings.json").write_text(json.dumps(bindings), encoding="utf-8")
        intents_path = self.root / "operation-intents.json"
        initialise_intents(intents_path, journal)
        update_intent(intents_path, journal, allocation_id=tokens["nt-alpha00000"], action="create")
        for store in ("lifecycle.json", "owner-bindings.json", "operation-intents.json"):
            (self.root / store).chmod(0o600)
        self.config["intent"] = str(intents_path)
        self.harness.namespaces["nt-alpha00000"] = {"device": 5, "inode": 9, "interfaces": {}}
        return tokens

    def test_boot_recovery_rolls_back_a_crashed_generation_and_reprovisions(self):
        self.half_built_fixture()
        report = self.restore()
        self.assertEqual(report["restored"], ["primary"])
        self.assertTrue(report["reconciled"])
        self.assertEqual(
            sorted(action["action"] for action in report["recovery"]["actions"] if "rollback" in action["action"]),
            ["rollback_deleted"],
        )
        self.assertEqual(report["recovery"]["review_required"], [])
        self.assertTrue(report["network_changes_applied"])
        self.assertNotIn("nt-alpha00000", self.harness.namespaces)


class PreservationSeamTests(cleanup_tests.CleanupTestBase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = __import__("pathlib").Path(self.temp.name)
        self.fixture = cleanup_tests.make_fixture(
            self.root, [cleanup_tests.LEGACY, cleanup_tests.ALPHA], APPLICATION_POLICY
        )
        self.harness = self.fixture["harness"]
        self.identity_patch = patch(
            "nord_tools_internal.nordvpn_ownership_verify._live_netns_identity",
            side_effect=self.harness.identity,
        )
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)
        self.desired = self.fixture["desired_policy"]

    def test_cleanup_preserves_the_shared_profile_generation(self):
        report = self.cleanup()
        self.assertEqual(
            sorted(entry["profile"] for entry in report["plan"]),
            ["legacy"] * 4,
        )
        report = self.cleanup(execute=True)
        self.assertEqual(
            [(kind, identifier) for kind, identifier in self.harness.deleted],
            [("namespace", "nt-legacy0000"), ("interface", "nthllegacy00")],
        )
        self.assertIn("nt-alpha00000", self.harness.namespaces)
        self.assertEqual(self.harness.host_links.get("nthlalpha000"), 41)

    def test_removing_an_application_is_pure_bookkeeping(self):
        pruned = dict(APPLICATION_POLICY)
        pruned["applications"] = {"app-b": APPLICATION_POLICY["applications"]["app-b"]}
        before = self.cleanup()
        self.fixture["desired_policy"] = pruned
        after = self.cleanup()
        self.assertEqual([entry["profile"] for entry in before["plan"]], ["legacy"] * 4)
        self.assertEqual(
            [(entry["identifier"], entry["action"]) for entry in before["plan"]],
            [(entry["identifier"], entry["action"]) for entry in after["plan"]],
        )
        self.assertEqual(self.harness.deleted, [])

    def test_repeated_runs_converge_identically(self):
        first = self.cleanup()
        self.cleanup(execute=True)
        second = self.cleanup()
        third = self.cleanup()
        self.assertEqual([entry["action"] for entry in first["plan"]], ["removable"] * 4)
        self.assertEqual(second["plan"], [])
        self.assertEqual(third["plan"], second["plan"])


class RecoveryCleanupSeamTests(cleanup_tests.CleanupTestBase):
    def test_a_lookalike_generation_refuses_cleanup_and_recovery_alike(self):
        self.harness.namespaces["nt-legacy0000"]["device"] = 9
        with self.assertRaises(ProvisioningUncertainError):
            self.cleanup(execute=True)
        self.assertIn("nt-legacy0000", self.harness.namespaces)
        report = self.cleanup()
        self.assertEqual(report["plan"], [])
        self.assertTrue(report["operator_review_required"])
        discovery = plan_recovery(
            self.fixture["journal"], self.fixture["bindings"], self.fixture["intent"], kernel=self.harness
        )
        self.assertTrue(discovery["operator_review_required"])
        self.assertFalse(discovery["executed"])


class TransientSeamTests(restore_tests.RestoreTestBase):
    def test_a_configured_transient_policy_influences_no_decision(self):
        runtime = self.root / "runtime"
        (runtime / "nord-tools").mkdir(parents=True)
        runtime_policy = runtime / "nord-tools" / "desired-policy.json"
        runtime_policy.write_text(
            json.dumps(
                {
                    "version": 1,
                    "defaults": {"vpn": "elsewhere"},
                    "vpn_profiles": {
                        "elsewhere": {"selection": {"mode": "country", "country": "gb"}, "sharing": "shared"}
                    },
                    "applications": {},
                }
            ),
            encoding="utf-8",
        )
        first = self.restore()
        runtime_policy.unlink()
        repeat = self.restore()
        self.assertEqual(first["decisions"], repeat["decisions"])


class TransientRefusalMatrixTests(unittest.TestCase):
    """No CLI fixture needed: transient refusal precedes every file access."""

    def call(self, *args):
        import contextlib
        import io

        output, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr):
            code = __import__("nordvpn_manage").main([*args])
        return code, output.getvalue(), stderr.getvalue()

    def test_every_lifecycle_command_refuses_transient_scope(self):
        matrix = [
            ("restore-startup", "--config", "somewhere.json"),
            ("cleanup", "--journal", "j", "--bindings", "b"),
            ("clear-ownership", "--config", "somewhere.json"),
            ("recovery", "--journal", "j", "--bindings", "b", "--intents", "i"),
        ]
        for command in matrix:
            code, output, stderr = self.call(*command, "--transient")
            self.assertEqual(code, 2, f"{command} accepted transient scope")
            self.assertIn("persistent-only", stderr, f"{command} did not refuse transient scope")


if __name__ == "__main__":
    unittest.main()
