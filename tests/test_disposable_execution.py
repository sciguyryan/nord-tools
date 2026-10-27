"""Journal-gated disposable session integration without privileged mutation."""

from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nord_tools_internal import nordvpn_disposable_execution as adapter
from nord_tools_internal.nordvpn_identity import allocate_identity
from nord_tools_internal.nordvpn_lifecycle import record_transition
from nord_tools_internal.nordvpn_operation_store import initialise_intents, read_intents
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification


class DisposableExecutionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = Path(temporary.name) / "operations.json"
        self.spec = TunnelSpecification(
            "nt-12345678",
            "ntwg1234",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "198.51.100.2",
            51820,
            "10.213.240.2/32",
            ("10.213.240.1/32",),
        )
        allocation = allocate_identity("interface", self.spec.interface, "default")
        self.token = allocation["allocation_id"]
        journal = {"version": 1, "allocations": {"version": 2, "resources": [allocation]}, "events": []}
        self.journal = record_transition(record_transition(journal, self.token, "reserved"), self.token, "creating")
        initialise_intents(self.store, self.journal)
        self.events = []

    def outcomes(self):
        return [item["outcome"] for item in read_intents(self.store, self.journal)["operations"]]

    def namespace(self, name):
        self.events.append("enter")

        @contextmanager
        def owned_namespace():
            class Owned:
                def verify(inner):
                    self.events.append("identity")

            try:
                yield Owned()
            finally:
                self.events.append("retired")

        return owned_namespace()

    def run_session(self, verifier=lambda _: True):
        with (
            patch.object(adapter, "disposable_namespace", side_effect=self.namespace),
            patch.object(
                adapter, "configure_disposable_wireguard", side_effect=lambda *args: self.events.append("configured")
            ),
        ):
            return adapter.execute_disposable_session(self.store, self.journal, self.token, self.spec, 3, verifier)

    def test_intent_precedes_mutation_and_retirement_precedes_completion(self):
        def verify(_):
            self.assertEqual(self.outcomes(), ["pending"])
            self.events.append("verified")
            return True

        self.assertEqual(self.run_session(verify), self.spec.namespace)
        self.assertEqual(self.events, ["enter", "configured", "identity", "verified", "identity", "retired"])
        self.assertEqual(self.outcomes(), ["completed"])

    def test_peer_mismatch_leaves_uncertain_intent(self):
        with self.assertRaisesRegex(RuntimeError, "peer verification"):
            self.run_session(lambda _: False)
        self.assertEqual(self.outcomes(), ["uncertain"])

    def test_failed_configuration_leaves_uncertain_intent(self):
        with (
            patch.object(adapter, "disposable_namespace", side_effect=self.namespace),
            patch.object(adapter, "configure_disposable_wireguard", side_effect=OSError("failure")),
            self.assertRaises(OSError),
        ):
            adapter.execute_disposable_session(self.store, self.journal, self.token, self.spec, 3, lambda _: True)
        self.assertEqual(self.outcomes(), ["uncertain"])

    def test_namespace_retirement_failure_preserves_uncertainty(self):
        @contextmanager
        def failed_retirement(_name):
            class Owned:
                def verify(self):
                    pass

            yield Owned()
            raise OSError("namespace retirement uncertain")

        with (
            patch.object(adapter, "disposable_namespace", side_effect=failed_retirement),
            patch.object(adapter, "configure_disposable_wireguard"),
            self.assertRaisesRegex(OSError, "retirement uncertain"),
        ):
            adapter.execute_disposable_session(self.store, self.journal, self.token, self.spec, 3, lambda _: True)
        self.assertEqual(self.outcomes(), ["uncertain"])
        with self.assertRaises(RegistryError):
            self.run_session()

    def test_mismatched_allocation_refused_before_mutation(self):
        other = TunnelSpecification(
            self.spec.namespace,
            "ntwg5678",
            self.spec.peer_public_key,
            self.spec.endpoint_address,
            self.spec.endpoint_port,
            self.spec.tunnel_address,
            self.spec.peer_allowed_ips,
        )
        with self.assertRaises(RegistryError):
            adapter.execute_disposable_session(self.store, self.journal, self.token, other, 3, lambda _: True)
        self.assertEqual(self.outcomes(), [])

    def test_missing_store_refuses_before_namespace_creation(self):
        self.store.unlink()
        with self.assertRaises(OSError):
            self.run_session()
        self.assertEqual(self.events, [])

    def test_retry_refused_after_uncertain_operation(self):
        with self.assertRaises(RuntimeError):
            self.run_session(lambda _: False)
        with self.assertRaises(RegistryError):
            self.run_session()
        self.assertEqual(self.events.count("enter"), 1)


if __name__ == "__main__":
    unittest.main()


class IsolatedDisposableExecutionTests(DisposableExecutionTests):
    def policy(self):
        from nord_tools_internal.nordvpn_failclosed_policy import NamespaceIsolationPolicy

        return NamespaceIsolationPolicy(
            self.spec.interface, "veth0", self.spec.endpoint_address, self.spec.endpoint_port
        )

    def test_firewall_precedes_wireguard_configuration(self):
        with (
            patch.object(adapter, "disposable_namespace", side_effect=self.namespace),
            patch.object(
                adapter, "install_disposable_isolation", side_effect=lambda *args: self.events.append("firewall")
            ),
            patch.object(
                adapter, "configure_disposable_wireguard", side_effect=lambda *args: self.events.append("configured")
            ),
        ):
            adapter.execute_isolated_disposable_session(
                self.store, self.journal, self.token, self.spec, 3, lambda _: True, self.policy()
            )
        self.assertEqual(self.events[:4], ["enter", "firewall", "identity", "configured"])
        self.assertEqual(self.outcomes(), ["completed"])

    def test_firewall_failure_blocks_wireguard_and_records_uncertainty(self):
        with (
            patch.object(adapter, "disposable_namespace", side_effect=self.namespace),
            patch.object(adapter, "install_disposable_isolation", side_effect=RuntimeError("nft failed")),
            patch.object(adapter, "configure_disposable_wireguard") as configure,
            self.assertRaisesRegex(RuntimeError, "nft failed"),
        ):
            adapter.execute_isolated_disposable_session(
                self.store, self.journal, self.token, self.spec, 3, lambda _: True, self.policy()
            )
        configure.assert_not_called()
        self.assertEqual(self.outcomes(), ["uncertain"])

    def test_policy_mismatch_refused_before_intent(self):
        from nord_tools_internal.nordvpn_failclosed_policy import NamespaceIsolationPolicy

        mismatch = NamespaceIsolationPolicy(self.spec.interface, "veth0", "198.51.100.99", self.spec.endpoint_port)
        with self.assertRaisesRegex(RegistryError, "does not match"):
            adapter.execute_isolated_disposable_session(
                self.store, self.journal, self.token, self.spec, 3, lambda _: True, mismatch
            )
        self.assertEqual(self.outcomes(), [])

    def test_isolated_entry_rejects_missing_policy(self):
        with self.assertRaisesRegex(RegistryError, "policy required"):
            adapter.execute_isolated_disposable_session(
                self.store, self.journal, self.token, self.spec, 3, lambda _: True, None
            )
        self.assertEqual(self.outcomes(), [])
