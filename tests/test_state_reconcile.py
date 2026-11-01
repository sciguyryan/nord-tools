"""Adversarial tests for persistent-state reconciliation against owned resources."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import nordvpn_manage
from nord_tools_internal.nordvpn_identity import allocate_identity
from nord_tools_internal.nordvpn_lifecycle import record_transition
from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership
from nord_tools_internal.nordvpn_state_reconcile import derive_actual_state, reconcile_desired
from nord_tools_internal.nordvpn_registry import RegistryError


CONFIG = {"selection": {"mode": "country", "country": "gb"}, "sharing": "shared"}


def policy(**profiles):
    base = {"version": 1, "defaults": {"vpn": "alpha"}, "vpn_profiles": {"alpha": dict(CONFIG)}, "applications": {}}
    for name, config in profiles.items():
        base["vpn_profiles"][name] = config
    return base


def snapshot(namespaces=(("nt-alpha", [("ntw0", 7)]),)):
    """A complete discovery-shaped observation for named namespaces."""
    return {
        "mode": "live_read_only",
        "network_changes_applied": False,
        "namespaces": [name for name, _ in namespaces],
        "host_interfaces": [],
        "namespace_details": [
            {"name": name, "interfaces": [{"name": iface, "index": index} for iface, index in links]}
            for name, links in namespaces
        ],
    }


def ecosystem(profile="alpha", ns_name="nt-alpha", iface_name="ntw0", configuration=CONFIG):
    """Build a complete, verified namespace-plus-interface ecosystem."""
    ns = allocate_identity("namespace", ns_name, profile)
    iface = allocate_identity("interface", iface_name, profile)
    journal = {"version": 1, "allocations": {"version": 2, "resources": [ns, iface]}, "events": []}
    for token in (ns["allocation_id"], iface["allocation_id"]):
        for state in ("reserved", "creating", "active"):
            journal = record_transition(journal, token, state)
    bindings = {
        "version": 1,
        "bindings": [
            {
                "allocation_id": ns["allocation_id"],
                "kind": "namespace",
                "identifier": ns_name,
                "binding": {"device": 5, "inode": 9},
                "configuration": configuration,
            },
            {
                "allocation_id": iface["allocation_id"],
                "kind": "interface",
                "identifier": iface_name,
                "binding": {"scope": ns_name, "ifindex": 7},
                "configuration": configuration,
            },
        ],
    }
    return journal, bindings


def preflight(journal, bindings, observed):
    bindings = bindings if isinstance(bindings, dict) else json.loads(bindings)
    identities = {
        entry["identifier"]: entry["binding"] for entry in bindings["bindings"] if entry["kind"] == "namespace"
    }
    for name in observed["namespaces"]:
        identities.setdefault(name, {"device": 5, "inode": 9})
    return preflight_ownership(journal, bindings, observed, netns_identity=identities)


class DerivedStateTests(unittest.TestCase):
    def setUp(self):
        self.journal, self.bindings = ecosystem()
        self.observed = snapshot()

    def actual(self):
        return derive_actual_state(self.journal, self.bindings, preflight(self.journal, self.bindings, self.observed))

    def test_derived_state_is_deterministic_and_non_authoritative(self):
        first, second = self.actual(), self.actual()
        self.assertEqual(first, json.loads(json.dumps(first)))
        self.assertEqual(first, second)
        self.assertFalse(first["network_changes_applied"])
        self.assertFalse(first["ownership_claim_authority"])
        self.assertEqual(sorted(first["profiles"]), ["alpha"])
        record = first["profiles"]["alpha"]
        self.assertEqual(len(record["present_resources"]), 2)
        self.assertEqual(record["blockers"], [])
        self.assertTrue(record["configuration_recorded"])
        self.assertEqual(record["recorded_configuration"], CONFIG)

    def test_missing_configuration_records_block_verification_grain(self):
        without_configuration = {
            "version": 1,
            "bindings": [
                {k: v for k, v in entry.items() if k != "configuration"} for entry in self.bindings["bindings"]
            ],
        }
        actual = derive_actual_state(
            self.journal, without_configuration, preflight(self.journal, without_configuration, self.observed)
        )
        record = actual["profiles"]["alpha"]
        self.assertFalse(record["configuration_recorded"])
        self.assertIsNone(record["recorded_configuration"])

    def test_partial_or_conflicting_configuration_records_are_unverified(self):
        partial = json.loads(json.dumps(self.bindings))
        del partial["bindings"][1]["configuration"]
        pristine = derive_actual_state(self.journal, partial, preflight(self.journal, partial, self.observed))
        self.assertFalse(pristine["profiles"]["alpha"]["configuration_recorded"])
        conflicting = json.loads(json.dumps(self.bindings))
        conflicting["bindings"][1]["configuration"] = dict(CONFIG, sharing="isolated")
        mixed = derive_actual_state(self.journal, conflicting, preflight(self.journal, conflicting, self.observed))
        self.assertFalse(mixed["profiles"]["alpha"]["configuration_recorded"])

    def test_unverified_resources_become_profile_blockers(self):
        empty_observed = snapshot(namespaces=())
        actual = derive_actual_state(
            self.journal, self.bindings, preflight(self.journal, self.bindings, empty_observed)
        )
        record = actual["profiles"]["alpha"]
        self.assertEqual(len(record["blockers"]), 2)
        self.assertFalse(any(b["finding"] == "verified_current" for b in record["blockers"]))
        # Nothing outside the claims is observed in this snapshot.
        self.assertEqual(actual["unclaimed"], [])


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.journal, self.bindings = ecosystem()
        self.actual = derive_actual_state(
            self.journal, self.bindings, preflight(self.journal, self.bindings, snapshot())
        )
        self.desired = policy()

    def reconcile(self, desired=None, actual=None, graph=None):
        return reconcile_desired(
            self.desired if desired is None else desired,
            self.actual if actual is None else actual,
            graph,
        )

    def test_verified_matching_state_converges(self):
        result = self.reconcile()
        self.assertTrue(result["reconciled"])
        self.assertFalse(result["requires_privileged_execution"])
        self.assertFalse(result["safe_to_execute"])
        self.assertTrue(result["transient_scope_excluded"])
        decision = result["decisions"][0]
        self.assertEqual(decision["profile"], "alpha")
        self.assertEqual(decision["action"], "converged")
        self.assertFalse(decision["requires_privileged_execution"])

    def test_repeated_runs_are_byte_identical(self):
        first = json.dumps(self.reconcile(), sort_keys=True)
        second = json.dumps(self.reconcile(), sort_keys=True)
        self.assertEqual(first, second)

    def test_configuration_drift_is_only_a_plan(self):
        result = self.reconcile(
            desired=policy(alpha={"selection": {"mode": "country", "country": "nl"}, "sharing": "shared"})
        )
        decision = result["decisions"][0]
        self.assertEqual(decision["action"], "configuration_changed")
        self.assertTrue(decision["requires_privileged_execution"])
        self.assertFalse(result["reconciled"])
        self.assertFalse(result["safe_to_execute"])
        self.assertTrue(result["requires_privileged_execution"])

    def test_unrecorded_configuration_cannot_claim_convergence(self):
        without_configuration = {
            "version": 1,
            "bindings": [
                {k: v for k, v in entry.items() if k != "configuration"} for entry in self.bindings["bindings"]
            ],
        }
        actual = derive_actual_state(
            self.journal, without_configuration, preflight(self.journal, without_configuration, snapshot())
        )
        result = self.reconcile(actual=actual)
        self.assertEqual(result["decisions"][0]["action"], "configuration_unverified")
        self.assertFalse(result["reconciled"])

    def test_blockers_block_the_profile_and_cannot_be_repaired_automatically(self):
        actual = derive_actual_state(
            self.journal, self.bindings, preflight(self.journal, self.bindings, snapshot(namespaces=()))
        )
        decision = self.reconcile(actual=actual)["decisions"][0]
        self.assertEqual(decision["action"], "blocked")
        self.assertIn("resource_missing", decision["reason"])
        self.assertFalse(decision["requires_privileged_execution"])

    def test_desired_profile_without_any_resources_is_never_created_blindly(self):
        desired = policy(
            alpha=dict(CONFIG), beta={"selection": {"mode": "country", "country": "nl"}, "sharing": "shared"}
        )
        result = reconcile_desired(desired, self.actual)
        beta = {item["profile"]: item for item in result["decisions"]}["beta"]
        self.assertEqual(beta["action"], "create_pending")
        self.assertIn("blind creation is prohibited", beta["reason"])
        self.assertTrue(beta["requires_privileged_execution"])
        self.assertFalse(result["safe_to_execute"])

    def test_undesired_verified_resources_are_retirement_plans_only(self):
        retired_profile_journal = json.loads(json.dumps(self.journal))
        extra = allocate_identity("namespace", "nt-oldname", "legacy")
        retired_profile_journal["allocations"]["resources"].append(extra)
        for state in ("reserved", "creating", "active"):
            retired_profile_journal = record_transition(retired_profile_journal, extra["allocation_id"], state)
        old_bindings = json.loads(json.dumps(self.bindings))
        old_bindings["bindings"].append(
            {
                "allocation_id": extra["allocation_id"],
                "kind": "namespace",
                "identifier": "nt-oldname",
                "binding": {"device": 6, "inode": 10},
                "configuration": dict(CONFIG),
            }
        )
        observed = snapshot(namespaces=(("nt-alpha", [("ntw0", 7)]), ("nt-oldname", [])))
        actual = derive_actual_state(
            retired_profile_journal, old_bindings, preflight(retired_profile_journal, old_bindings, observed)
        )
        result = self.reconcile(actual=actual)
        decisions = {item["profile"]: item for item in result["decisions"]}
        self.assertEqual(decisions["legacy"]["action"], "retire_pending")
        self.assertTrue(decisions["legacy"]["requires_privileged_execution"])
        self.assertEqual(decisions["alpha"]["action"], "converged")
        self.assertFalse(result["safe_to_execute"])

    def test_undesired_unverified_resources_are_reported_and_left_alone(self):
        stale_journal = json.loads(json.dumps(self.journal))
        stale = allocate_identity("namespace", "nt-stale", "stale")
        stale_journal["allocations"]["resources"].append(stale)
        stale_journal = record_transition(stale_journal, stale["allocation_id"], "reserved")
        result = self.reconcile(
            actual=derive_actual_state(
                stale_journal, self.bindings, preflight(stale_journal, self.bindings, snapshot())
            )
        )
        decision = {item["profile"]: item for item in result["decisions"]}["stale"]
        self.assertEqual(decision["action"], "blocked")
        self.assertIn("left alone", decision["reason"])
        self.assertFalse(decision["requires_privileged_execution"])

    def test_retired_verified_resources_mean_creation_is_required_again(self):
        retired_journal = json.loads(json.dumps(self.journal))
        for token in [a["allocation_id"] for a in retired_journal["allocations"]["resources"]]:
            for state in ("retiring", "retired"):
                retired_journal = record_transition(retired_journal, token, state)
        actual = derive_actual_state(
            retired_journal, self.bindings, preflight(retired_journal, self.bindings, snapshot(namespaces=()))
        )
        decision = self.reconcile(actual=actual)["decisions"][0]
        self.assertEqual(decision["action"], "create_pending")
        self.assertTrue(decision["requires_privileged_execution"])


class DependencyPropagationTests(unittest.TestCase):
    def test_blocked_prerequisite_blocks_its_dependents(self):
        journal, bindings = ecosystem()
        gamma = allocate_identity("namespace", "nt-gamma", "gamma")
        journal = json.loads(json.dumps(journal))
        journal["allocations"]["resources"].append(gamma)
        journal = record_transition(journal, gamma["allocation_id"], "reserved")
        desired = policy(
            alpha=dict(CONFIG), gamma={"selection": {"mode": "country", "country": "ie"}, "sharing": "shared"}
        )
        actual = derive_actual_state(
            journal,
            bindings,
            preflight(journal, bindings, snapshot(namespaces=(("nt-alpha", [("ntw0", 7)]), ("nt-gamma", [])))),
        )
        graph = {"version": 1, "dependencies": {"alpha": ["gamma"], "gamma": []}}
        result = reconcile_desired(desired, actual, graph)
        decisions = {item["profile"]: item for item in result["decisions"]}
        self.assertEqual(decisions["gamma"]["action"], "blocked")
        self.assertEqual(decisions["alpha"]["action"], "blocked")
        self.assertIn("blocked prerequisite profiles: gamma", decisions["alpha"]["reason"])

    def test_graph_must_enumerate_every_desired_and_derived_profile(self):
        journal, bindings = ecosystem()
        actual = derive_actual_state(journal, bindings, preflight(journal, bindings, snapshot()))
        with self.assertRaises(RegistryError):
            reconcile_desired(policy(), actual, {"version": 1, "dependencies": {}})
        cyclic = {"version": 1, "dependencies": {"alpha": ["alpha"]}}
        with self.assertRaises(RegistryError):
            reconcile_desired(policy(), actual, cyclic)


class ValidationTests(unittest.TestCase):
    def test_incompatible_inputs_are_refused(self):
        journal, bindings = ecosystem()
        preflight_result = preflight(journal, bindings, snapshot())
        with self.assertRaises(RegistryError):
            derive_actual_state(journal, bindings, {"mode": "wrong"})
        with self.assertRaises(RegistryError):
            derived = derive_actual_state(journal, bindings, preflight_result)
            reconcile_desired(policy(), derived | {"mode": "wrong"})
        incomplete_preflight = json.loads(json.dumps(preflight_result))
        incomplete_preflight["resources"] = []
        with self.assertRaises(RegistryError):
            derive_actual_state(journal, bindings, incomplete_preflight)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        self.journal, self.bindings = ecosystem()
        self.observed = snapshot()
        self.journal_path = self.root / "lifecycle.json"
        self.bindings_path = self.root / "owner-bindings.json"
        self.journal_path.write_text(json.dumps(self.journal), encoding="utf-8")
        self.bindings_path.write_text(json.dumps(self.bindings), encoding="utf-8")
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text(json.dumps(policy()), encoding="utf-8")
        self.env = patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.root / "config")})
        self.env.start()
        self.addCleanup(self.env.stop)

    def call(self, *args, discover_result=None):
        output, stderr = io.StringIO(), io.StringIO()
        # The offline test host has no /run/netns; resolve the live mount
        # identity from the fixture bindings so the full CLI path runs.
        identities = {
            entry["identifier"]: dict(entry["binding"])
            for entry in self.bindings["bindings"]
            if entry["kind"] == "namespace"
        }
        with (
            patch.object(
                nordvpn_manage, "discover", return_value=self.observed if discover_result is None else discover_result
            ) as discovery,
            patch(
                "nord_tools_internal.nordvpn_ownership_verify._live_netns_identity",
                side_effect=lambda name: identities[name],
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(stderr),
        ):
            code = nordvpn_manage.main(["reconcile-live", *args])
        return code, output.getvalue(), stderr.getvalue(), discovery

    def test_transient_intent_is_never_reconciled(self):
        code, output, stderr, discovery = self.call(
            "--transient", "--journal", str(self.journal_path), "--bindings", str(self.bindings_path)
        )
        self.assertEqual(code, 2)
        self.assertIn("transient intent is never reconciled", stderr)
        self.assertEqual(output, "")
        discovery.assert_not_called()

    def test_without_persistent_policy_the_command_fails_closed(self):
        code, output, stderr, _ = self.call("--journal", str(self.journal_path), "--bindings", str(self.bindings_path))
        self.assertEqual(code, 2)
        self.assertIn("no saved persistent policy", stderr)

    def test_full_flow_is_read_only_and_reports_the_saved_convergence(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(nordvpn_manage.main(["configure", "--policy", str(self.policy_path)]), 0)
        journal_before = self.journal_path.read_bytes()
        bindings_before = self.bindings_path.read_bytes()
        code, output, _, discovery = self.call(
            "--journal", str(self.journal_path), "--bindings", str(self.bindings_path)
        )
        self.assertEqual(code, 0)
        discovery.assert_called_once_with()
        result = json.loads(output)
        self.assertEqual(result["scope"], "persistent")
        self.assertTrue(result["reconciled"])
        self.assertFalse(result["safe_to_execute"])
        self.assertEqual(result["decisions"][0]["action"], "converged")
        # The reconciliation run must not mutate the journal or the bindings.
        self.assertEqual(self.journal_path.read_bytes(), journal_before)
        self.assertEqual(self.bindings_path.read_bytes(), bindings_before)

    def test_cli_reports_configuration_drift_as_a_plan(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(nordvpn_manage.main(["configure", "--policy", str(self.policy_path)]), 0)
        self.policy_path.write_text(
            json.dumps(policy(alpha={"selection": {"mode": "country", "country": "nl"}, "sharing": "shared"})),
            encoding="utf-8",
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(nordvpn_manage.main(["configure", "--policy", str(self.policy_path)]), 0)
        code, output, _, _ = self.call("--journal", str(self.journal_path), "--bindings", str(self.bindings_path))
        self.assertEqual(code, 0)
        result = json.loads(output)
        self.assertFalse(result["reconciled"])
        self.assertTrue(result["requires_privileged_execution"])
        self.assertEqual(result["decisions"][0]["action"], "configuration_changed")


if __name__ == "__main__":
    unittest.main()
