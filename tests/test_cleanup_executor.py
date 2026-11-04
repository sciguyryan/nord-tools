"""Adversarial tests for ownership-aware cleanup, reset and preservation."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import nordvpn_manage
from nord_tools_internal.nordvpn_cleanup_executor import (
    ProvisioningUncertainError,
    plan_cleanup,
    reset_ownership,
)
from nord_tools_internal.nordvpn_identity import allocate_identity
from nord_tools_internal.nordvpn_lifecycle import record_transition
from nord_tools_internal.nordvpn_operation_store import initialise_intents
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_startup import initialise_startup_runs

CONFIG = {"selection": {"mode": "country", "country": "gb"}, "sharing": "shared"}
LEGACY = ("legacy", "nt-legacy0000", "ntwglegacy00", "ntlulegacy00", "nthllegacy00", {})
ALPHA = ("alpha", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", {"ifindex": 41})


def policy(**profiles):
    base = {
        "version": 1,
        "defaults": {"vpn": "alpha"},
        "vpn_profiles": {"alpha": dict(CONFIG)},
        "applications": {},
    }
    for name, config in profiles.items():
        base["vpn_profiles"][name] = config
    return base


def ecosystem(profile, ns_name, wg_name, ul_name, host_name, *, device=5, inode=9, ifindex=40):
    """One complete verified generation: namespace, two ns ifaces and one host end."""
    resources = [
        allocate_identity("namespace", ns_name, profile),
        allocate_identity("interface", wg_name, profile),
        allocate_identity("interface", ul_name, profile),
        allocate_identity("interface", host_name, profile),
    ]
    journal = {"version": 1, "allocations": {"version": 2, "resources": resources}, "events": []}
    for resource in resources:
        for state in ("reserved", "creating", "active"):
            journal = record_transition(journal, resource["allocation_id"], state)
    bindings = {
        "version": 1,
        "bindings": [
            {
                "allocation_id": resources[0]["allocation_id"],
                "kind": "namespace",
                "identifier": ns_name,
                "binding": {"device": device, "inode": inode},
                "configuration": dict(CONFIG),
            },
            {
                "allocation_id": resources[1]["allocation_id"],
                "kind": "interface",
                "identifier": wg_name,
                "binding": {"scope": ns_name, "ifindex": 7},
                "configuration": dict(CONFIG),
            },
            {
                "allocation_id": resources[2]["allocation_id"],
                "kind": "interface",
                "identifier": ul_name,
                "binding": {"scope": ns_name, "ifindex": 8},
                "configuration": dict(CONFIG),
            },
            {
                "allocation_id": resources[3]["allocation_id"],
                "kind": "interface",
                "identifier": host_name,
                "binding": {"scope": "host", "ifindex": ifindex},
                "configuration": dict(CONFIG),
            },
        ],
    }
    tokens = {resource["identifier"]: resource["allocation_id"] for resource in resources}
    return resources, journal, bindings, tokens


class CleanupHarness:
    """A deterministic in-memory stand-in for the privileged kernel surface."""

    def __init__(self):
        self.namespaces: dict[str, dict] = {}
        self.host_links: dict[str, int] = {}
        self.resolvers: dict[str, str] = {}
        self.deleted: list[tuple[str, str]] = []
        self.fail_on: set[str] = set()

    def add_profile(self, ns_name, wg_name, ul_name, host_name, device=5, inode=9, ifindex=40):
        self.namespaces[ns_name] = {"device": device, "inode": inode, "interfaces": {wg_name: 7, ul_name: 8}}
        self.host_links[host_name] = ifindex

    def identity(self, name):
        record = self.namespaces.get(name)
        if record is None:
            return None
        return {"device": record["device"], "inode": record["inode"]}

    def observe(self):
        return {
            "mode": "live_read_only",
            "network_changes_applied": False,
            "namespaces": sorted(self.namespaces),
            "host_interfaces": [{"name": name, "index": index} for name, index in sorted(self.host_links.items())],
            "namespace_details": [
                {
                    "name": name,
                    "interfaces": [
                        {"name": iface, "index": index} for iface, index in sorted(record["interfaces"].items())
                    ],
                }
                for name, record in sorted(self.namespaces.items())
            ],
        }

    def netns_identity(self, name):
        return self.identity(name)

    def delete_namespace(self, name, binding):
        record = self.namespaces.get(name)
        if record is None or (binding["device"], binding["inode"]) != (record["device"], record["inode"]):
            raise RegistryError(f"namespace {name} does not match its recorded owner binding")
        if name in self.fail_on:
            raise ProvisioningUncertainError(f"injected failure while deleting {name}")
        del self.namespaces[name]
        self.deleted.append(("namespace", name))

    def delete_host_interface(self, name, ifindex):
        if name in self.fail_on:
            raise ProvisioningUncertainError(f"injected failure while deleting {name}")
        if self.host_links.get(name) != ifindex:
            raise RegistryError(f"interface {name} index changed before deletion")
        del self.host_links[name]
        self.deleted.append(("interface", name))

    def resolver_state(self, name):
        return self.resolvers.get(name, "absent")

    def remove_resolver(self, name):
        if name in self.fail_on:
            raise ProvisioningUncertainError(f"injected failure while removing resolver {name}")
        del self.resolvers[name]
        self.deleted.append(("resolver", name))


def merged_events(merged, part_events):
    """Merge one ecosystem's lifecycle events after another's sequence order."""
    offset = len(merged)
    return merged + [{**event, "sequence": event["sequence"] + offset} for event in part_events]


def make_fixture(root, profiles, desired_polffix):
    """Create a complete offline ecosystem: stores, intent store and kernel."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    journal_doc = {"version": 1, "allocations": {"version": 2, "resources": []}, "events": []}
    bindings_doc = {"version": 1, "bindings": []}
    harness = CleanupHarness()
    tokens = {}
    for name, ns_name, wg_name, ul_name, host_name, options in profiles:
        resources, part_journal, part_bindings, part_tokens = ecosystem(
            name, ns_name, wg_name, ul_name, host_name, **options
        )
        tokens.update(part_tokens)
        for resource in resources:
            journal_doc["allocations"]["resources"].append(resource)
        journal_doc["events"] = merged_events(journal_doc["events"], part_journal["events"])
        bindings_doc["bindings"].extend(part_bindings["bindings"])
        harness.add_profile(ns_name, wg_name, ul_name, host_name, **options)
    journal_path = root / "lifecycle.json"
    bindings_path = root / "owner-bindings.json"
    intents_path = root / "operation-intents.json"
    run_record_path = root / "startup-runs.json"
    journal_path.write_text(json.dumps(journal_doc), encoding="utf-8")
    bindings_path.write_text(json.dumps(bindings_doc), encoding="utf-8")
    initialise_intents(intents_path, journal_doc)
    initialise_startup_runs(run_record_path)
    return {
        "journal": journal_path,
        "bindings": bindings_path,
        "intent": intents_path,
        "run_record": run_record_path,
        "desired_policy": desired_polffix,
        "harness": harness,
        "tokens": tokens,
    }


class CleanupTestBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = make_fixture(self.root, [LEGACY, ALPHA], policy())
        self.harness = self.fixture["harness"]
        self.desired = self.fixture["desired_policy"]
        self.identity_patch = patch(
            "nord_tools_internal.nordvpn_ownership_verify._live_netns_identity", side_effect=self.harness.identity
        )
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)

    def cleanup(self, **kwargs):
        options = dict(
            intent_path=self.fixture["intent"],
            desired_policy=self.desired,
            kernel=self.harness,
            recorded_at="2026-11-02T00:00:00+00:00",
        )
        options.update(kwargs)
        return plan_cleanup(self.fixture["journal"], self.fixture["bindings"], **options)

    def reload(self, path, name):
        return json.loads(Path(path / name).read_text(encoding="utf-8"))


class SelectedProfileLifecycleTests(CleanupTestBase):
    def test_selection_preserves_other_profiles_and_can_retire_a_desired_profile(self):
        plan = self.cleanup(selected_profiles=("alpha",))
        self.assertEqual({item["profile"] for item in plan["plan"]}, {"alpha"})
        self.assertEqual({item["profile"] for item in plan["preserved"]}, {"legacy"})
        result = self.cleanup(selected_profiles=("alpha",), execute=True)
        self.assertEqual({item["profile"] for item in result["deletions"]}, {"alpha"})
        self.assertIn("nt-legacy0000", self.harness.namespaces)
        self.assertNotIn("nt-alpha00000", self.harness.namespaces)

    def test_empty_selection_is_non_destructive(self):
        report = self.cleanup(selected_profiles=(), execute=True)
        self.assertFalse(report["deletions"])
        self.assertIn("nt-alpha00000", self.harness.namespaces)
        self.assertIn("nt-legacy0000", self.harness.namespaces)

    def test_selected_prerequisite_is_blocked_by_unselected_dependent(self):
        graph = self.root / "shared-graph.json"
        graph.write_text(
            json.dumps({"version": 1, "dependencies": {"alpha": ["legacy"], "legacy": []}}),
            encoding="utf-8",
        )
        report = self.cleanup(selected_profiles=("legacy",), graph_path=graph)
        self.assertEqual(report["plan"], [])
        self.assertEqual({entry["profile"] for entry in report["preserved"]}, {"alpha"})
        self.assertEqual({entry["profile"] for entry in report["review_required"]}, {"legacy"})
        with self.assertRaises(ProvisioningUncertainError):
            self.cleanup(selected_profiles=("legacy",), graph_path=graph, execute=True)
        self.assertEqual(self.harness.deleted, [])

    def test_selected_dependent_can_retire_without_removing_prerequisite(self):
        graph = self.root / "shared-graph.json"
        graph.write_text(
            json.dumps({"version": 1, "dependencies": {"alpha": ["legacy"], "legacy": []}}),
            encoding="utf-8",
        )
        report = self.cleanup(selected_profiles=("alpha",), graph_path=graph, execute=True)
        self.assertEqual({entry["profile"] for entry in report["deletions"]}, {"alpha"})
        self.assertIn("nt-legacy0000", self.harness.namespaces)
        self.assertNotIn("nt-alpha00000", self.harness.namespaces)

    def test_selected_retirement_failure_preserves_unselected_profile(self):
        self.harness.fail_on.add("nt-alpha00000")
        with self.assertRaises(ProvisioningUncertainError):
            self.cleanup(selected_profiles=("alpha",), execute=True)
        self.assertIn("nt-legacy0000", self.harness.namespaces)
        self.assertEqual(self.harness.deleted, [])

    def test_selected_retirement_is_idempotent(self):
        self.cleanup(selected_profiles=("alpha",), execute=True)
        deleted = list(self.harness.deleted)
        second = self.cleanup(selected_profiles=("alpha",), execute=True)
        self.assertEqual(second["deletions"], [])
        self.assertEqual(self.harness.deleted, deleted)
        self.assertIn("nt-legacy0000", self.harness.namespaces)

    def test_unknown_and_duplicate_selection_refused(self):
        for names in (("missing",), ("alpha", "alpha"), ("",), ["alpha"]):
            with self.subTest(names=names), self.assertRaises(RegistryError):
                self.cleanup(selected_profiles=names)


class CleanupPlanTests(CleanupTestBase):
    def test_the_plan_is_exact_for_the_undesired_profile(self):
        report = self.cleanup()
        self.assertFalse(report["executed"])
        self.assertEqual(report["mode"], "ownership_cleanup")
        self.assertEqual(
            [(entry["identifier"], entry["action"]) for entry in report["plan"]],
            [
                ("nt-legacy0000", "removable"),
                ("nthllegacy00", "removable"),
                ("ntlulegacy00", "removable"),
                ("ntwglegacy00", "removable"),
            ],
        )
        self.assertEqual(
            [entry["action"] for entry in report["preserved"]],
            ["preserved"] * 4,
        )
        self.assertFalse(report["review_required"])
        self.assertFalse(report["operator_review_required"])
        self.assertEqual(
            sorted(entry["profile"] for entry in report["preserved"]),
            ["alpha"] * 4,
        )

    def test_the_completed_run_preserves_the_desired_profile(self):
        report = self.cleanup(execute=True)
        self.assertEqual(
            sorted(entry["identifier"] for entry in report["preserved"] if "alpha" in entry["profile"]),
            ["nt-alpha00000", "nthlalpha000", "ntlualpha000", "ntwgalpha000"],
        )
        self.assertTrue(self.harness.namespaces["nt-alpha00000"])
        self.assertNotIn("nt-legacy0000", self.harness.namespaces)

    def test_unclaimed_observations_are_preserved(self):
        self.harness.namespaces["nt-foreign4001"] = {"device": 9, "inode": 400, "interfaces": {}}
        report = self.cleanup()
        self.assertEqual(report["unclaimed"], [{"kind": "namespace", "identifier": "nt-foreign4001"}])
        self.assertFalse(any(entry["identifier"] == "nt-foreign4001" for entry in report["plan"]))
        # The foreign namespace remains untouched even after execution.
        self.cleanup(execute=True)
        self.assertIn("nt-foreign4001", self.harness.namespaces)


class CleanupExecutionTests(CleanupTestBase):
    def test_execution_deletes_only_verified_unwanted_resources(self):
        report = self.cleanup(execute=True)
        self.assertTrue(report["executed"])
        self.assertTrue(report["network_changes_applied"])
        self.assertEqual(
            [(kind, identifier) for kind, identifier in self.harness.deleted],
            [("namespace", "nt-legacy0000"), ("interface", "nthllegacy00")],
        )
        states = {
            event["allocation_id"]: event["state"]
            for event in self.fixture["journal"].read_text()
            and json.loads(self.fixture["journal"].read_text())["events"]
        }
        self.assertEqual(sorted(set(states.values())), ["active", "retired"])
        intents = json.loads(self.fixture["intent"].read_text())["operations"]
        self.assertEqual([(item["action"], item["outcome"]) for item in intents], [("retire", "completed")] * 4)
        self.assertFalse(report["operator_review_required"])

    def test_resolvers_are_removed_only_with_explicit_confirmation(self):
        self.harness.resolvers["nt-legacy0000"] = "clean"
        self.cleanup(execute=True)
        # Without confirmation the namespace is deleted but its resolver stays.
        self.assertIn("nt-legacy0000", self.harness.resolvers)
        self.assertNotIn("nt-legacy0000", self.harness.namespaces)
        # A fresh ecosystem is cleaned entirely once confirmation is explicit.
        fresh = make_fixture(self.root / "fresh", [LEGACY], policy())
        fresh["harness"].resolvers["nt-legacy0000"] = "clean"
        with patch(
            "nord_tools_internal.nordvpn_ownership_verify._live_netns_identity",
            side_effect=fresh["harness"].identity,
        ):
            plan_cleanup(
                fresh["journal"],
                fresh["bindings"],
                intent_path=fresh["intent"],
                desired_policy=fresh["desired_policy"],
                kernel=fresh["harness"],
                resolvers=True,
                execute=True,
                recorded_at="2026-11-02T00:00:00+00:00",
            )
        self.assertNotIn("nt-legacy0000", fresh["harness"].resolvers)
        self.assertTrue(any(kind == "resolver" for kind, _ in fresh["harness"].deleted))

    def test_unexpected_resolver_state_refuses_before_deletion(self):
        self.harness.resolvers["nt-legacy0000"] = "unexpected"
        with self.assertRaises(ProvisioningUncertainError):
            self.cleanup(execute=True, resolvers=True)
        self.assertIn("nt-legacy0000", self.harness.namespaces)
        self.assertEqual(self.harness.deleted, [])

    def test_repeatability_converges_to_an_empty_second_run(self):
        self.cleanup(execute=True)
        self.harness.deleted.clear()
        repeat = self.cleanup()
        self.assertEqual(repeat["plan"], [])
        self.assertFalse(repeat["executed"])
        self.assertFalse(repeat["network_changes_applied"])
        self.assertEqual(len(self.harness.deleted), 0)


class CleanupFailureTests(CleanupTestBase):
    def test_disputed_profile_is_fully_reviewed_never_partially_deleted(self):
        self.harness.namespaces["nt-legacy0000"]["device"] = 9
        report = self.cleanup()
        self.assertEqual(
            sorted(entry["identifier"] for entry in report["review_required"]),
            ["nt-legacy0000", "nthllegacy00", "ntlulegacy00", "ntwglegacy00"],
        )
        self.assertEqual(report["plan"], [])
        with self.assertRaises(ProvisioningUncertainError):
            self.cleanup(execute=True)
        self.assertEqual(self.harness.deleted, [])
        states = {
            event["allocation_id"]: event["state"]
            for event in json.loads(self.fixture["journal"].read_text(encoding="utf-8"))["events"]
        }
        self.assertEqual(set(states.values()), {"active"})

    def test_partial_failure_stops_and_marks_uncertainty(self):
        failures = make_fixture(
            Path(str(self.root)) / "failure",
            [
                ("onefail", "nt-onefail000", "ntwgonefail0", "ntluonefail0", "nthlonefail0", {}),
                ("twofail", "nt-twofail000", "ntwgtwofail0", "ntlutwofail0", "nthltwofail0", {"ifindex": 45}),
            ],
            policy(),
        )
        failures["harness"].fail_on.add("nt-twofail000")
        with (
            patch(
                "nord_tools_internal.nordvpn_ownership_verify._live_netns_identity",
                side_effect=failures["harness"].identity,
            ),
            self.assertRaises(ProvisioningUncertainError),
        ):
            plan_cleanup(
                failures["journal"],
                failures["bindings"],
                intent_path=failures["intent"],
                desired_policy=failures["desired_policy"],
                kernel=failures["harness"],
                execute=True,
                recorded_at="2026-11-02T00:00:00+00:00",
            )
        journal = json.loads(failures["journal"].read_text())
        identifiers = {
            resource["identifier"]: resource["allocation_id"] for resource in journal["allocations"]["resources"]
        }
        states = {event["allocation_id"]: event["state"] for event in journal["events"]}
        self.assertEqual(
            {states[identifiers[name]] for name in ("nt-onefail000", "ntwgonefail0", "ntluonefail0", "nthlonefail0")},
            {"retired"},
        )
        self.assertEqual(
            {states[identifiers[name]] for name in ("nt-twofail000", "ntwgtwofail0", "ntlutwofail0", "nthltwofail0")},
            {"retiring"},
        )
        intents = json.loads(failures["intent"].read_text())["operations"]
        self.assertEqual(
            sorted(item["outcome"] for item in intents),
            ["completed"] * 4 + ["uncertain"] * 4,
        )
        # Only the successful profile's kernel resources were deleted.
        self.assertEqual(
            [(kind, identifier) for kind, identifier in failures["harness"].deleted],
            [("namespace", "nt-onefail000"), ("interface", "nthlonefail0")],
        )
        self.assertIn("nt-twofail000", failures["harness"].namespaces)

    def test_dependency_preservation_blocks_the_prerequisite(self):
        graph_path = self.root / "graph.json"
        graph_path.write_text(
            json.dumps({"version": 1, "dependencies": {"alpha": ["legacy"], "legacy": []}}),
            encoding="utf-8",
        )
        report = self.cleanup(graph_path=graph_path)
        self.assertEqual(report["plan"], [])
        self.assertEqual(
            [entry["reason"] for entry in report["review_required"] if entry["profile"] == "legacy"],
            ["the dependent profile alpha remains in place and requires it"] * 4,
        )


class ResetTests(CleanupTestBase):
    def test_reset_plans_every_owned_resource(self):
        report = reset_ownership(
            self.startup_config(),
            kernel=self.harness,
            recorded_at="2026-11-02T00:00:00+00:00",
        )
        self.assertEqual(report["mode"], "ownership_reset")
        self.assertEqual(
            sorted(entry["profile"] for entry in report["plan"]),
            ["alpha"] * 4 + ["legacy"] * 4,
        )
        self.assertFalse(report["executed"])
        self.assertEqual(self.harness.deleted, [])

    def test_full_reset_teardown_archives_and_reinitialises_the_stores(self):
        before_bindings_json = json.loads(self.fixture["bindings"].read_text())
        report = reset_ownership(
            self.startup_config(),
            kernel=self.harness,
            execute=True,
            recorded_at="2026-11-02T00:00:00+00:00",
        )
        self.assertTrue(report["executed"])
        archive = Path(report["stores_reset"]["archive"])
        self.assertEqual(
            sorted(path.name for path in archive.iterdir()),
            ["bindings.json", "intents.json", "journal.json", "run_record.json"],
        )
        # The archive holds the exact pre-reset state the teardown left behind.
        archived_journal = json.loads((archive / "journal.json").read_text())
        states = {event["allocation_id"]: event["state"] for event in archived_journal["events"]}
        self.assertEqual(set(states.values()), {"retired"})
        self.assertEqual(json.loads((archive / "bindings.json").read_text()), before_bindings_json)
        archived_intents = json.loads((archive / "intents.json").read_text())["operations"]
        self.assertEqual(len(archived_intents), 8)
        self.assertTrue(all(item["outcome"] == "completed" for item in archived_intents))
        self.assertEqual(os.stat(archive / "journal.json").st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.fixture["journal"].read_text())["allocations"]["resources"], [])
        self.assertEqual(json.loads(self.fixture["bindings"].read_text())["bindings"], [])
        self.assertEqual(json.loads(self.fixture["intent"].read_text())["operations"], [])
        self.assertEqual(json.loads(self.fixture["run_record"].read_text())["runs"], [])
        self.assertEqual(self.harness.namespaces, {})
        self.assertEqual(self.harness.host_links, {})

    def test_reset_refuses_while_review_obligations_exist(self):
        self.harness.namespaces["nt-legacy0000"]["device"] = 9
        with self.assertRaises(ProvisioningUncertainError):
            reset_ownership(
                self.startup_config(),
                kernel=self.harness,
                execute=True,
                recorded_at="2026-11-02T00:00:00+00:00",
            )
        self.assertIn("nt-legacy0000", self.harness.namespaces)

    def startup_config(self):
        return {
            "version": 1,
            "policy": str(self.root / "desired-policy.json"),
            "journal": str(self.fixture["journal"]),
            "bindings": str(self.fixture["bindings"]),
            "intent": str(self.fixture["intent"]),
            "run_record": str(self.fixture["run_record"]),
            "tunnels": {},
            "credentials": {},
        }


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        config_home = self.root / "config"
        config_home.mkdir()
        self.policy_path = config_home / "nord-tools" / "desired-policy.json"
        self.policy_path.parent.mkdir()
        self.policy_path.write_text(json.dumps(policy()), encoding="utf-8")
        self.env = patch.dict(os.environ, {"XDG_CONFIG_HOME": str(config_home)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def call(self, *args):
        output, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr):
            code = nordvpn_manage.main([*args])
        return code, output.getvalue(), stderr.getvalue()

    def test_transient_is_rejected_for_cleanup_and_reset(self):
        code, output, stderr = self.call("cleanup", "--journal", "j", "--bindings", "b", "--transient")
        self.assertEqual(code, 2)
        self.assertIn("cleanup is persistent-only", stderr)
        code, output, stderr = self.call("clear-ownership", "--config", "c", "--transient")
        self.assertEqual(code, 2)
        self.assertIn("clear-ownership is persistent-only", stderr)

    def test_cleanup_requires_a_saved_persistent_policy(self):
        fixture = make_fixture(self.root, [LEGACY, ALPHA], policy())
        (self.root / "config" / "nord-tools" / "desired-policy.json").unlink()
        code, output, stderr = self.call(
            "cleanup", "--journal", str(fixture["journal"]), "--bindings", str(fixture["bindings"])
        )
        self.assertEqual(code, 2)
        self.assertIn("requires a saved persistent policy", stderr)

    def test_cleanup_execution_requires_the_intents_store(self):
        fixture = make_fixture(self.root, [LEGACY, ALPHA], policy())
        code, output, stderr = self.call(
            "cleanup", "--journal", str(fixture["journal"]), "--bindings", str(fixture["bindings"]), "--execute"
        )
        self.assertEqual(code, 2)
        self.assertIn("requires the operation intent store", stderr)


if __name__ == "__main__":
    unittest.main()


class ConsumerAwareCleanupTests(CleanupTestBase):
    """Consumer release evidence must block unsafe selected retirement."""

    def test_shared_reference_blocks_selected_retirement(self):
        consumer_policy = {
            "version": 1,
            "defaults": {"vpn": "alpha"},
            "vpn_profiles": {"alpha": dict(CONFIG)},
            "applications": {
                "browser": {"executable": "/usr/bin/browser"},
                "editor": {"executable": "/usr/bin/editor"},
            },
        }
        with self.assertRaisesRegex(RegistryError, "still retain"):
            self.cleanup(
                selected_profiles=("alpha",),
                consumer_policy=consumer_policy,
                released_consumers=("browser",),
                execute=True,
            )
        self.assertEqual(self.harness.deleted, [])

    def test_complete_release_allows_existing_verified_plan(self):
        consumer_policy = {
            "version": 1,
            "defaults": {"vpn": "alpha"},
            "vpn_profiles": {"alpha": dict(CONFIG)},
            "applications": {
                "browser": {"executable": "/usr/bin/browser"},
                "editor": {"executable": "/usr/bin/editor"},
            },
        }
        report = self.cleanup(
            selected_profiles=("alpha",), consumer_policy=consumer_policy, released_consumers=("editor", "browser")
        )
        self.assertEqual({entry["profile"] for entry in report["plan"]}, {"alpha"})
        self.assertEqual(self.harness.deleted, [])

    def test_missing_release_evidence_is_refused(self):
        consumer_policy = {
            "version": 1,
            "defaults": {"vpn": "alpha"},
            "vpn_profiles": {"alpha": dict(CONFIG)},
            "applications": {},
        }
        with self.assertRaisesRegex(RegistryError, "lack released consumer evidence"):
            self.cleanup(selected_profiles=("alpha",), consumer_policy=consumer_policy, released_consumers=())
        with self.assertRaisesRegex(RegistryError, "supplied together"):
            self.cleanup(selected_profiles=("alpha",), consumer_policy=consumer_policy)
        with self.assertRaisesRegex(RegistryError, "explicit selected"):
            self.cleanup(consumer_policy=consumer_policy, released_consumers=())
