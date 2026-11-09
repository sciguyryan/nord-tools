"""Failure-injection tests for crash, restart and interrupted-cleanup recovery."""

import contextlib
import io
import json
import os

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import nordvpn_manage
from nord_tools_internal.nordvpn_cleanup_executor import CleanupKernel
from nord_tools_internal.nordvpn_identity import allocate_identity
from nord_tools_internal.nordvpn_lifecycle import record_transition
from nord_tools_internal.nordvpn_operation_store import initialise_intents, update_intent
from nord_tools_internal.nordvpn_recovery_executor import (
    ProvisioningUncertainError,
    plan_recovery,
)
from nord_tools_internal.nordvpn_registry import RegistryError

CONFIG = {"selection": {"mode": "country", "country": "gb"}, "sharing": "shared"}


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


_CHAPTERS = {
    "reserved": [],
    "creating": ["creating"],
    "active": ["creating", "active"],
    "retiring": ["creating", "active", "retiring"],
    "retired": ["creating", "active", "retiring", "retired"],
}


def ecosystem(profile, ns_name, wg_name, ul_name, host_name, *, states="active", ifindex=40):
    """One profile generation with the requested lifecycle state for each token."""
    resources = [
        allocate_identity("namespace", ns_name, profile),
        allocate_identity("interface", wg_name, profile),
        allocate_identity("interface", ul_name, profile),
        allocate_identity("interface", host_name, profile),
    ]
    journal = {"version": 1, "allocations": {"version": 2, "resources": resources}, "events": []}
    for resource in resources:
        journal = record_transition(journal, resource["allocation_id"], "reserved")
        for state in _CHAPTERS[states]:
            journal = record_transition(journal, resource["allocation_id"], state)
    bindings = {
        "version": 1,
        "bindings": [
            {
                "allocation_id": resources[0]["allocation_id"],
                "kind": "namespace",
                "identifier": ns_name,
                "binding": {"device": 5, "inode": 9},
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
    return journal, bindings, tokens


class RecoveryHarness(CleanupKernel):
    """Cleanup-kernel-shaped deterministic kernel for recovery tests."""

    def __init__(self):
        self.namespaces: dict[str, dict] = {}
        self.host_links: dict[str, int] = {}
        self.resolvers: dict[str, str] = {}
        self.deleted: list[tuple[str, str]] = []

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

    def netns_identity(self, name, netns_dir=None):
        record = self.namespaces.get(name)
        if record is None:
            return None
        return {"device": record["device"], "inode": record["inode"]}

    def delete_namespace(self, name, binding):
        record = self.namespaces.get(name)
        if record is None or (binding["device"], binding["inode"]) != (record["device"], record["inode"]):
            raise RegistryError(f"namespace {name} does not match its recorded owner binding")
        del self.namespaces[name]
        self.deleted.append(("namespace", name))

    def delete_host_interface(self, name, ifindex):
        if self.host_links.get(name) != ifindex:
            raise RegistryError(f"interface {name} index changed before deletion")
        del self.host_links[name]
        self.deleted.append(("interface", name))

    def resolver_state(self, name):
        return self.resolvers.get(name, "absent")

    def remove_resolver(self, name):
        del self.resolvers[name]
        self.deleted.append(("resolver", name))


class RecoveryTestBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.harness = RecoveryHarness()
        self.identity_patch = patch(
            "nord_tools_internal.nordvpn_ownership_verify._live_netns_identity",
            side_effect=self.harness.netns_identity,
        )
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)

    def make_fixture(self, journal, bindings, *, namespace_name, wg_name, ul_name, host_name):
        journal_path = self.root / "lifecycle.json"
        bindings_path = self.root / "owner-bindings.json"
        intents_path = self.root / "operation-intents.json"
        journal_path.write_text(json.dumps(journal), encoding="utf-8")
        bindings_path.write_text(json.dumps(bindings), encoding="utf-8")
        initialise_intents(intents_path, journal)
        self.harness.namespaces[namespace_name] = {
            "device": 5,
            "inode": 9,
            "interfaces": {wg_name: 7, ul_name: 8},
        }
        self.harness.host_links[host_name] = 40
        tokens = {resource["identifier"]: resource["allocation_id"] for resource in journal["allocations"]["resources"]}
        return {"journal": journal_path, "bindings": bindings_path, "intent": intents_path, "tokens": tokens}

    def pending_create_intent(self, fixture, namespace_token):
        update_intent(
            fixture["intent"],
            json.loads(fixture["journal"].read_text()),
            allocation_id=namespace_token,
            action="create",
        )

    def pending_retire_intent(self, fixture, token):
        journal = json.loads(fixture["journal"].read_text())
        update_intent(fixture["intent"], journal, allocation_id=token, action="retire")

    def mark_uncertain(self, fixture):
        with open(fixture["intent"], encoding="utf-8") as source:
            intents = json.load(source)
        intents["operations"][0]["outcome"] = "uncertain"
        fixture["intent"].write_text(json.dumps(intents), encoding="utf-8")

    def recover(self, fixture, **kwargs):
        options = dict(kernel=self.harness, recorded_at="2026-11-02T00:00:00+00:00")
        options.update(kwargs)
        return plan_recovery(fixture["journal"], fixture["bindings"], fixture["intent"], **options)

    def journal_states(self, fixture):
        return {
            event["allocation_id"]: event["state"]
            for event in json.loads(fixture["journal"].read_text(encoding="utf-8"))["events"]
        }

    def intent_outcomes(self, fixture):
        return [
            operation["outcome"]
            for operation in json.loads(fixture["intent"].read_text(encoding="utf-8"))["operations"]
        ]


class CreationCrashTests(RecoveryTestBase):
    def a_crash_after_recordings(self, *, outcome="pending"):
        journal, bindings, tokens = ecosystem(
            "alpha", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", states="creating"
        )
        fixture = self.make_fixture(
            journal,
            bindings,
            namespace_name="nt-alpha00000",
            wg_name="ntwgalpha000",
            ul_name="ntlualpha000",
            host_name="nthlalpha000",
        )
        self.pending_create_intent(fixture, tokens["nt-alpha00000"])
        if outcome == "uncertain":
            self.mark_uncertain(fixture)
        return fixture

    def test_a_complete_creation_crash_finishes_its_bookkeeping_at_boot(self):
        fixture = self.a_crash_after_recordings()
        report = self.recover(fixture, boot=True, execute=True)
        self.assertTrue(report["executed"])
        self.assertFalse(report["operator_review_required"])
        self.assertEqual(
            sorted(action["action"] for action in report["actions"]),
            ["completed_bookkeeping"] * 4,
        )
        self.assertTrue(all(state == "active" for state in self.journal_states(fixture).values()))
        self.assertEqual(self.intent_outcomes(fixture), ["completed"])
        self.assertEqual(self.harness.deleted, [])

    def test_boot_never_touches_uncertain_create_outcomes(self):
        fixture = self.a_crash_after_recordings(outcome="uncertain")
        with self.assertRaises(ProvisioningUncertainError):
            self.recover(fixture, boot=True, execute=True)
        self.assertTrue(all(state == "creating" for state in self.journal_states(fixture).values()))
        self.assertEqual(self.intent_outcomes(fixture), ["uncertain"])
        self.assertEqual(self.harness.deleted, [])
        # The operator's explicitly executed recovery resolves it by evidence.
        report = self.recover(fixture, execute=True)
        self.assertFalse(report["operator_review_required"])
        self.assertEqual(self.intent_outcomes(fixture), ["completed"])
        self.assertTrue(all(state == "active" for state in self.journal_states(fixture).values()))

    def test_an_absent_pending_creation_resolves_by_records_only(self):
        journal, bindings, tokens = ecosystem(
            "alpha", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", states="creating"
        )
        fixture = self.make_fixture(
            journal,
            bindings,
            namespace_name="nt-absent-unused",
            wg_name="ntwgunused000",
            ul_name="ntluunused000",
            host_name="nthlunused000",
        )
        # The kernel holds nothing under the claimed names: the crash happened
        # before any kernel change, which the fresh observation certifies.
        self.harness.namespaces.clear()
        self.harness.host_links.clear()
        self.pending_create_intent(fixture, tokens["nt-alpha00000"])
        report = self.recover(fixture, boot=True, execute=True)
        self.assertTrue(report["executed"])
        self.assertEqual(
            sorted({action["action"] for action in report["actions"]}),
            ["resolved_create_failed", "resolved_records"],
        )
        self.assertEqual(set(self.journal_states(fixture).values()), {"retired"})
        self.assertEqual(self.intent_outcomes(fixture), ["failed"])
        self.assertEqual(self.harness.deleted, [])

    def test_an_unrecorded_live_creation_is_never_adopted(self):
        journal, bindings, tokens = ecosystem(
            "alpha", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", states="creating"
        )
        bindings = {"version": 1, "bindings": []}
        fixture = self.make_fixture(
            journal,
            bindings,
            namespace_name="nt-alpha00000",
            wg_name="ntwgalpha000",
            ul_name="ntlualpha000",
            host_name="nthlalpha000",
        )
        self.pending_create_intent(fixture, tokens["nt-alpha00000"])
        report = self.recover(fixture)
        dispositions = sorted({item["disposition"] for item in report["items"] if item["outcome"] == "pending"})
        self.assertIn("review_required", dispositions)
        self.assertTrue(report["operator_review_required"])
        report = self.recover(fixture, execute=True)
        self.assertIn("nt-alpha00000", self.harness.namespaces)
        self.assertEqual(self.harness.deleted, [])
        self.assertTrue(report["operator_review_required"])


class HalfBuiltCreationTests(RecoveryTestBase):
    def half_built(self, *, outcome="pending"):
        journal, bindings, tokens = ecosystem(
            "alpha", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", states="creating"
        )
        bindings = {
            "version": 1,
            "bindings": [entry for entry in bindings["bindings"] if entry["kind"] == "namespace"],
        }
        fixture = self.make_fixture(
            journal,
            bindings,
            namespace_name="nt-alpha00000",
            wg_name="ntwgalpha000",
            ul_name="ntlualpha000",
            host_name="nthlalpha000",
        )
        self.witness_host = "nthlalpha000"
        self.pending_create_intent(fixture, tokens["nt-alpha00000"])
        if outcome == "uncertain":
            self.mark_uncertain(fixture)
        # The half-built namespace holds no interface yet: the crash preceded them.
        self.harness.namespaces["nt-alpha00000"]["interfaces"] = {}
        return fixture

    def test_a_pending_half_built_creation_rolls_back_and_closes_records(self):
        fixture = self.half_built()
        self.harness.host_links["nthlwitness"] = 44  # a foreign host interface must stay
        self.recover(fixture, boot=True, execute=True)
        self.assertNotIn("nt-alpha00000", self.harness.namespaces)
        self.assertEqual(
            self.harness.deleted,
            [("namespace", "nt-alpha00000")],
        )
        self.assertEqual(set(self.journal_states(fixture).values()), {"retired"})
        self.assertEqual(self.intent_outcomes(fixture), ["failed"])
        # Nothing outside the rolled-back generation was touched.
        self.assertEqual(self.harness.host_links["nthlwitness"], 44)

    def test_uncertain_half_built_creations_need_the_operator(self):
        fixture = self.half_built(outcome="uncertain")
        with self.assertRaises(ProvisioningUncertainError):
            self.recover(fixture, boot=True, execute=True)
        self.assertIn("nt-alpha00000", self.harness.namespaces)
        self.recover(fixture, execute=True)
        self.assertNotIn("nt-alpha00000", self.harness.namespaces)
        self.assertEqual(self.intent_outcomes(fixture), ["failed"])
        self.assertEqual(set(self.journal_states(fixture).values()), {"retired"})

    def test_repeat_recovery_runs_converge_to_no_items(self):
        fixture = self.half_built()
        self.recover(fixture, boot=True, execute=True)
        repeat = self.recover(fixture, boot=True, execute=True)
        self.assertEqual(repeat["items"], [])
        self.assertFalse(repeat["network_changes_applied"])
        self.assertEqual(repeat["actions"], [])
        self.assertEqual(self.harness.deleted, [("namespace", "nt-alpha00000")])

    def test_operator_recovery_closes_a_partially_bound_generation_already_rolled_back(self):
        journal, bindings, tokens = ecosystem(
            "alpha", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", states="creating"
        )
        bindings = {
            "version": 1,
            "bindings": [entry for entry in bindings["bindings"] if entry["identifier"] != "ntwgalpha000"],
        }
        fixture = self.make_fixture(
            journal,
            bindings,
            namespace_name="nt-alpha00000",
            wg_name="ntwgalpha000",
            ul_name="ntlualpha000",
            host_name="nthlalpha000",
        )
        self.pending_create_intent(fixture, tokens["nt-alpha00000"])
        self.mark_uncertain(fixture)
        journal = json.loads(fixture["journal"].read_text(encoding="utf-8"))
        for token in tokens.values():
            journal = record_transition(journal, token, "failed")
        fixture["journal"].write_text(json.dumps(journal), encoding="utf-8")
        self.harness.namespaces.clear()
        self.harness.host_links.clear()

        with self.assertRaises(ProvisioningUncertainError):
            self.recover(fixture, boot=True, execute=True)
        report = self.recover(fixture, execute=True)

        self.assertFalse(report["operator_review_required"])
        self.assertEqual(set(self.journal_states(fixture).values()), {"retired"})
        self.assertEqual(self.intent_outcomes(fixture), ["failed"])
        self.assertEqual(self.harness.deleted, [])


class RetirementCrashTests(RecoveryTestBase):
    def cleanup_crash(self, *, outcome="pending", kernel=("present",), binding_kept=True):
        journal, bindings, tokens = ecosystem(
            "alpha", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", states="retiring"
        )
        if not binding_kept:
            bindings = {"version": 1, "bindings": []}
        fixture = self.make_fixture(
            journal,
            bindings,
            namespace_name="nt-alpha00000",
            wg_name="ntwgalpha000",
            ul_name="ntlualpha000",
            host_name="nthlalpha000",
        )
        if kernel == ("present",):
            pass
        elif kernel == ("absent",):
            self.harness.namespaces.clear()
            self.harness.host_links.clear()
        elif kernel == ("lookalike",):
            self.harness.namespaces["nt-alpha00000"]["device"] = 9
        update_intent(
            fixture["intent"],
            json.loads(fixture["journal"].read_text()),
            allocation_id=tokens["nt-alpha00000"],
            action="retire",
        )
        if outcome == "uncertain":
            self.mark_uncertain(fixture)
        return fixture

    def test_retirement_resumes_by_operator_and_wipes_the_generation(self):
        fixture = self.cleanup_crash()
        with self.assertRaises(ProvisioningUncertainError):
            self.recover(fixture, boot=True, execute=True)
        self.assertIn("nt-alpha00000", self.harness.namespaces)
        report = self.recover(fixture, execute=True)
        self.assertTrue(report["executed"])
        self.assertTrue(any(action["action"] == "retirement_completed" for action in report["actions"]))
        self.assertNotIn("nt-alpha00000", self.harness.namespaces)
        self.assertEqual(self.intent_outcomes(fixture), ["completed"])
        self.assertEqual(set(self.journal_states(fixture).values()), {"retired"})
        # Host-side state was never touched during a namespace-only resume.
        self.assertEqual(self.harness.host_links, {})

    def test_absent_retiring_resources_complete_as_records(self):
        fixture = self.cleanup_crash(kernel=("absent",))
        report = self.recover(fixture, boot=True, execute=True)
        self.assertEqual(set(self.journal_states(fixture).values()), {"retired"})
        self.assertEqual(self.intent_outcomes(fixture), ["completed"])
        self.assertEqual(self.harness.deleted, [])
        self.assertFalse(report["operator_review_required"])

    def test_a_lookalike_under_a_recorded_retirement_is_never_deleted(self):
        fixture = self.cleanup_crash(kernel=("lookalike",))
        report = self.recover(fixture)
        dispositions = sorted({item["disposition"] for item in report["items"]})
        self.assertIn("review_required", dispositions)
        self.assertTrue(report["operator_review_required"])
        report = self.recover(fixture, execute=True)
        self.assertIn("nt-alpha00000", self.harness.namespaces)
        self.assertEqual(self.harness.deleted, [])
        self.assertTrue(report["operator_review_required"])

    def test_uncertain_retirements_require_the_operator_at_boot(self):
        fixture = self.cleanup_crash(outcome="uncertain", kernel=("absent",))
        with self.assertRaises(ProvisioningUncertainError):
            self.recover(fixture, boot=True, execute=True)
        self.assertEqual(self.intent_outcomes(fixture), ["uncertain"])
        report = self.recover(fixture, execute=True)
        self.assertEqual(self.intent_outcomes(fixture), ["completed"])
        self.assertFalse(report["operator_review_required"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.root / "config")})
        self.env.start()
        self.addCleanup(self.env.stop)

    def call(self, *args):
        output, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr):
            code = nordvpn_manage.main([*args])
        return code, output.getvalue(), stderr.getvalue()

    def test_transient_is_rejected(self):
        code, output, stderr = self.call(
            "recovery", "--journal", "j", "--bindings", "b", "--intents", "i", "--transient"
        )
        self.assertEqual(code, 2)
        self.assertIn("persistent-only", stderr)

    def test_the_intent_store_is_mandatory(self):
        with self.assertRaises(SystemExit) as expected:
            self.call("recovery", "--journal", "j", "--bindings", "b")
        self.assertEqual(expected.exception.code, 2)


if __name__ == "__main__":
    unittest.main()


class PristineGenerationRecoveryTests(RecoveryTestBase):
    def test_pending_namespace_before_kernel_mutation_retires_staged_dependants(self):
        journal, bindings, tokens = ecosystem(
            "alpha", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", states="creating"
        )
        bindings["bindings"] = []
        fixture = self.make_fixture(
            journal,
            bindings,
            namespace_name="nt-alpha00000",
            wg_name="ntwgalpha000",
            ul_name="ntlualpha000",
            host_name="nthlalpha000",
        )
        self.harness.namespaces.clear()
        self.harness.host_links.clear()
        self.pending_create_intent(fixture, tokens["nt-alpha00000"])
        result = self.recover(fixture, boot=True, execute=True)
        self.assertFalse(result["operator_review_required"])
        self.assertEqual(set(self.journal_states(fixture).values()), {"retired"})
        self.assertEqual(self.intent_outcomes(fixture), ["failed"])
        self.assertEqual(self.harness.deleted, [])
        self.assertEqual(self.recover(fixture, boot=True, execute=True)["actions"], [])

    def test_unbound_host_lookalike_blocks_pristine_generation_retirement(self):
        journal, bindings, tokens = ecosystem(
            "alpha", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", states="creating"
        )
        bindings["bindings"] = []
        fixture = self.make_fixture(
            journal,
            bindings,
            namespace_name="nt-alpha00000",
            wg_name="ntwgalpha000",
            ul_name="ntlualpha000",
            host_name="nthlalpha000",
        )
        self.harness.namespaces.clear()
        self.harness.host_links["nthlalpha000"] = 99
        self.pending_create_intent(fixture, tokens["nt-alpha00000"])
        with self.assertRaises(ProvisioningUncertainError):
            self.recover(fixture, boot=True, execute=True)
        self.assertIn("creating", self.journal_states(fixture).values())
        self.assertEqual(self.harness.deleted, [])


class UnboundStagedGenerationTests(RecoveryTestBase):
    """The pre-kernel checkpoint leaves a staged generation without bindings."""

    def staged(self):
        journal, _, tokens = ecosystem(
            "alpha", "nt-alpha00000", "ntwgalpha000", "ntlualpha000", "nthlalpha000", states="creating"
        )
        fixture = self.make_fixture(
            journal,
            {"version": 1, "bindings": []},
            namespace_name="nt-alpha00000",
            wg_name="ntwgalpha000",
            ul_name="ntlualpha000",
            host_name="nthlalpha000",
        )
        self.harness.namespaces.clear()
        self.harness.host_links.clear()
        self.pending_create_intent(fixture, tokens["nt-alpha00000"])
        return fixture

    def test_absent_staged_dependants_converge_without_kernel_mutation(self):
        fixture = self.staged()
        report = self.recover(fixture, boot=True, execute=True)
        self.assertFalse(report["operator_review_required"])
        self.assertEqual(set(self.journal_states(fixture).values()), {"retired"})
        self.assertEqual(self.intent_outcomes(fixture), ["failed"])
        self.assertEqual(self.harness.deleted, [])
        repeated = self.recover(fixture, boot=True, execute=True)
        self.assertEqual(repeated["actions"], [])

    def test_uncertain_staged_generation_requires_operator_recovery(self):
        fixture = self.staged()
        self.mark_uncertain(fixture)
        plan = self.recover(fixture, boot=True)
        staged = [item for item in plan["items"] if item["action"] == "bookkeeping"]
        self.assertTrue(staged)
        self.assertTrue(all(item["authority"] == "operator" for item in staged))
        with self.assertRaises(ProvisioningUncertainError):
            self.recover(fixture, boot=True, execute=True)
        self.assertIn("creating", self.journal_states(fixture).values())
        self.assertEqual(self.intent_outcomes(fixture), ["uncertain"])
        self.assertEqual(self.harness.deleted, [])

    def test_retired_history_does_not_block_recreated_generation_recovery(self):
        old_resources = ecosystem(
            "alpha", "nt-oldalpha00", "ntwgoldalpha", "ntluoldalpha", "nthloldalpha", states="retired"
        )[0]["allocations"]["resources"]
        new_resources = ecosystem(
            "alpha", "nt-newalpha00", "ntwgnewalpha", "ntlunewalpha", "nthlnewalpha", states="creating"
        )[0]["allocations"]["resources"]
        journal = {
            "version": 1,
            "allocations": {"version": 2, "resources": [*old_resources, *new_resources]},
            "events": [],
        }
        for resource in old_resources:
            for state in ("reserved", "creating", "active", "retiring", "retired"):
                journal = record_transition(journal, resource["allocation_id"], state)
        for resource in new_resources:
            for state in ("reserved", "creating"):
                journal = record_transition(journal, resource["allocation_id"], state)
        fixture = self.make_fixture(
            journal,
            {"version": 1, "bindings": []},
            namespace_name="nt-newalpha00",
            wg_name="ntwgnewalpha",
            ul_name="ntlunewalpha",
            host_name="nthlnewalpha",
        )
        self.harness.namespaces.clear()
        self.harness.host_links.clear()
        self.pending_create_intent(fixture, fixture["tokens"]["nt-newalpha00"])

        report = self.recover(fixture, boot=True, execute=True)

        self.assertFalse(report["operator_review_required"])
        self.assertEqual(set(self.journal_states(fixture).values()), {"retired"})
        self.assertEqual(self.intent_outcomes(fixture), ["failed"])
        self.assertEqual(self.harness.deleted, [])

    def test_unbound_live_host_name_blocks_dependent_retirement(self):
        fixture = self.staged()
        self.harness.host_links["nthlalpha000"] = 91
        report = self.recover(fixture, boot=True)
        self.assertTrue(report["operator_review_required"])
        self.assertEqual(self.journal_states(fixture)[fixture["tokens"]["nthlalpha000"]], "creating")
        self.assertEqual(self.harness.deleted, [])
