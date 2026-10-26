"""Failure-oriented checks for journal-gated experimental execution."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nord_tools_internal.nordvpn_identity import allocate_identity
from nord_tools_internal.nordvpn_lifecycle import record_transition
from nord_tools_internal.nordvpn_operation_store import initialise_intents, read_intents
from nord_tools_internal.nordvpn_provision_execution import ProvisioningUncertainError, execute_recorded_creation
from nord_tools_internal.nordvpn_registry import RegistryError


class ProvisionExecutionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Path(directory.name) / "intents.json"
        allocation = allocate_identity("interface", "ntwg0", "default")
        self.token = allocation["allocation_id"]
        base = {"version": 1, "allocations": {"version": 2, "resources": [allocation]}, "events": []}
        self.journal = record_transition(record_transition(base, self.token, "reserved"), self.token, "creating")
        initialise_intents(self.store, self.journal)

    def outcomes(self):
        return [item["outcome"] for item in read_intents(self.store, self.journal)["operations"]]

    def test_persists_pending_before_invocation_and_completion_after_verification(self):
        observed = []

        def operation():
            observed.append(self.outcomes())
            return "created"

        self.assertEqual(
            execute_recorded_creation(
                self.store, self.journal, self.token, operation, lambda value: value == "created"
            ),
            "created",
        )
        self.assertEqual(observed, [["pending"]])
        self.assertEqual(self.outcomes(), ["completed"])

    def test_missing_store_never_invokes_operation(self):
        self.store.unlink()
        with self.assertRaises(OSError):
            execute_recorded_creation(
                self.store, self.journal, self.token, lambda: self.fail("mutated"), lambda _: True
            )

    def test_operation_exception_is_uncertain_and_blocks_retry(self):
        def fail():
            raise RuntimeError("kernel result unknown")

        with self.assertRaisesRegex(RuntimeError, "kernel result unknown"):
            execute_recorded_creation(self.store, self.journal, self.token, fail, lambda _: True)
        self.assertEqual(self.outcomes(), ["uncertain"])
        with self.assertRaises(RegistryError):
            execute_recorded_creation(
                self.store, self.journal, self.token, lambda: self.fail("retried"), lambda _: True
            )

    def test_unverified_result_is_uncertain(self):
        with self.assertRaises(ProvisioningUncertainError):
            execute_recorded_creation(self.store, self.journal, self.token, lambda: "created", lambda _: False)
        self.assertEqual(self.outcomes(), ["uncertain"])

    def test_invalid_lifecycle_refuses_before_mutation(self):
        base = {"version": 1, "allocations": self.journal["allocations"], "events": self.journal["events"][:1]}
        with self.assertRaises(RegistryError):
            execute_recorded_creation(self.store, base, self.token, lambda: self.fail("mutated"), lambda _: True)

    def test_completion_write_failure_reports_uncertain(self):
        from nord_tools_internal import nordvpn_provision_execution as execution

        real_update = execution.update_intent

        def update(*args, **kwargs):
            if kwargs.get("outcome") == "completed":
                raise OSError("disk full")
            return real_update(*args, **kwargs)

        with (
            patch.object(execution, "update_intent", side_effect=update),
            self.assertRaises(ProvisioningUncertainError),
        ):
            execute_recorded_creation(self.store, self.journal, self.token, lambda: "created", lambda _: True)
        self.assertEqual(self.outcomes(), ["pending"])


if __name__ == "__main__":
    unittest.main()
