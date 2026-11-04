"""Adversarial tests for the authorised boot restoration executor."""

import base64
import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import nordvpn_manage
from nord_tools_internal.nordvpn_namespace_ownership import OwnershipError
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_cleanup_executor import CleanupKernel
from nord_tools_internal.nordvpn_restore_executor import restore_boot_state
from nord_tools_internal.nordvpn_underlay_install import UnderlayError

_KEY = base64.b64encode(secrets.token_bytes(32)).decode("ascii")


class FakeOwned:
    """Descriptor-shaped stand-in for a created namespace's authority."""

    def __init__(self, harness, name, device, inode):
        self.harness = harness
        self.name = name
        self.device = device
        self.inode = inode
        self.closed = False

    def verify(self):
        if self.closed or self.name not in self.harness.namespaces:
            raise OwnershipError("namespace is no longer observable")

    def retire(self):
        self.verify()
        del self.harness.namespaces[self.name]
        self.closed = True

    def release(self):
        if not self.closed:
            self.closed = True


class KernelHarness:
    """A deterministic in-memory stand-in for the privileged kernel surface."""

    def __init__(self):
        self.namespaces: dict[str, dict] = {}
        self.host_links: dict[str, int] = {}
        self.next_index = 20
        self.isolation: list[tuple[str, str]] = []
        self.routes: list[tuple[str, str]] = []
        self.tunnels: list[tuple[str, str, str]] = []

    def observe(self) -> dict:
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

    def identity(self, name: str) -> dict:
        record = self.namespaces.get(name)
        if record is None:
            raise RegistryError(f"namespace mount {name} is not observable")
        return {"device": record["device"], "inode": record["inode"]}

    def create_namespace(self, name: str):
        if name in self.namespaces:
            raise OwnershipError("namespace already exists")
        record = {"device": 5 + len(self.namespaces), "inode": 100 + len(self.namespaces), "interfaces": {}}
        self.namespaces[name] = record
        return FakeOwned(self, name, record["device"], record["inode"])

    def prepare_underlay(
        self, namespace: str, ns_interface: str, host_interface: str, ns_address: str, host_address: str
    ) -> int:
        if host_interface in self.host_links:
            raise UnderlayError("host interface name already exists")
        self.next_index += 2
        self.namespaces[namespace]["interfaces"][ns_interface] = self.next_index
        self.host_links[host_interface] = self.next_index + 1
        return self.next_index

    def install_isolation(self, owned, policy) -> object:
        owned.verify()
        self.isolation.append((owned.name, policy.tunnel_interface, policy.underlay_interface))
        return object()

    def route_tunnel(self, namespace, tunnel_interface, underlay_interface, endpoint, tunnel_address, gateway):
        # Mirror iproute2: a route cannot target a device not yet created.
        if tunnel_interface not in self.namespaces[namespace]["interfaces"]:
            raise UnderlayError("cannot route through an absent WireGuard interface")
        if not any(item[0] == namespace for item in self.isolation):
            raise UnderlayError("routing before fail-closed isolation")
        self.routes.append((namespace, tunnel_interface, underlay_interface, gateway))

    def configure_wireguard(self, specification, owned, key_fd: int) -> None:
        owned.verify()
        key = os.read(key_fd, 46).strip()
        # The real primitive creates the interface inside the namespace and brings it up.
        self.next_index += 1
        self.namespaces[specification.namespace]["interfaces"][specification.interface] = self.next_index
        self.tunnels.append((specification.namespace, specification.interface, key.decode("ascii")))

    def interface_index(self, namespace: str, interface: str) -> int:
        try:
            return self.namespaces[namespace]["interfaces"][interface]
        except KeyError as exc:
            raise UnderlayError("interface absent from the namespace") from exc

    def public_key_from_fd(self, fd: int) -> str:
        key = os.read(fd, 46).strip()
        return f"pub-{key.decode('ascii')}"

    def verify_wireguard(
        self, namespace: str, interface: str, expected_public_key: str, peer_public_key: str, specification=None
    ) -> bool:
        return (
            any(record[:2] == (namespace, interface) and record[2] == _KEY for record in self.tunnels)
            and expected_public_key == f"pub-{_KEY}"
        )

    def remove_host_interface(self, name: str) -> None:
        self.host_links.pop(name, None)

    def delete_namespace(self, name: str, binding: dict) -> None:
        record = self.namespaces.get(name)
        if record is None or (binding["device"], binding["inode"]) != (record["device"], record["inode"]):
            raise RegistryError(f"namespace {name} does not match its recorded owner binding")
        del self.namespaces[name]

    def delete_host_interface(self, name: str, ifindex: int) -> None:
        if self.host_links.get(name) != ifindex:
            raise RegistryError(f"interface {name} index changed before deletion")
        del self.host_links[name]

    def wipe_kernel(self) -> None:
        """Simulate a reboot: no namespace or host link survives."""
        self.namespaces.clear()
        self.host_links.clear()


def cleanup_surface(harness) -> CleanupKernel:
    """Adapt the restore harness to the cleanup kernel contract for recovery."""
    return CleanupKernel(
        observe=harness.observe,
        netns_identity=harness.identity,
        delete_namespace=harness.delete_namespace,
        delete_host_interface=harness.delete_host_interface,
        resolver_state=lambda name: "absent",
        remove_resolver=lambda name: None,
    )


class RestoreTestBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "defaults": {"vpn": "primary"},
                    "vpn_profiles": {
                        "primary": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}
                    },
                    "applications": {},
                }
            ),
            encoding="utf-8",
        )
        self.credential_path = self.root / "probe.key"
        self.credential_path.write_bytes(_KEY.encode("ascii"))
        os.chmod(self.credential_path, 0o600)
        self.config = {
            "version": 1,
            "policy": str(self.policy_path),
            "journal": str(self.root / "lifecycle.json"),
            "bindings": str(self.root / "owner-bindings.json"),
            "intent": str(self.root / "operation-intents.json"),
            "run_record": str(self.root / "startup-runs.json"),
            "tunnels": {
                "primary": {
                    "peer_public_key": _KEY[:43] + "=",
                    "endpoint_address": "198.51.100.10",
                    "endpoint_port": 51820,
                    "tunnel_address": "10.213.240.2/32",
                    "peer_allowed_ips": ["10.213.240.1/32"],
                    "underlay": {"namespace_address": "10.214.0.2/30", "host_address": "10.214.0.1/30"},
                }
            },
            "credentials": {"primary": str(self.credential_path)},
        }
        self.harness = KernelHarness()
        self.identity_patch = patch(
            "nord_tools_internal.nordvpn_ownership_verify._live_netns_identity", side_effect=self.harness.identity
        )
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)

    def restore(
        self, harness=None, boot_id="00000000-0000-0000-0000-000000000001", recorded_at="2026-11-02T00:00:00+00:00"
    ):
        chosen = harness or self.harness
        return restore_boot_state(
            self.config, kernel=chosen, cleanup_kernel=cleanup_surface(chosen), boot_id=boot_id, recorded_at=recorded_at
        )

    def load(self, name: str) -> dict:
        return json.loads((self.root / name).read_text(encoding="utf-8"))


class FirstBootRestorationTests(RestoreTestBase):
    def test_provisions_the_pinned_profile_and_converges(self):
        report = self.restore()
        self.assertEqual(report["mode"], "startup_restoration_report")
        self.assertEqual(report["restored"], ["primary"])
        self.assertTrue(report["network_changes_applied"])
        self.assertTrue(report["reconciled"])
        self.assertFalse(report["operator_review_required"])
        decision = report["decisions"][0]
        self.assertEqual((decision["profile"], decision["action"]), ("primary", "converged"))
        self.assertEqual(len(self.harness.isolation), 1)
        # Order: the firewall is installed before tunnel configuration.
        self.assertNotIn((self.harness.isolation[0][1],), self.harness.routes)

    def test_the_full_store_state_is_recorded_for_recovery(self):
        self.restore()
        journal = self.load("lifecycle.json")
        allocations = journal["allocations"]["resources"]
        self.assertEqual({resource["profile"] for resource in allocations}, {"primary"})
        self.assertEqual(len(allocations), 4)
        self.assertEqual({resource["kind"] for resource in allocations}, {"namespace", "interface"})
        states = {event["allocation_id"]: event["state"] for event in journal["events"]}
        self.assertEqual(len(states), 4)
        self.assertTrue(all(state == "active" for state in states.values()))

        bindings = self.load("owner-bindings.json")["bindings"]
        self.assertEqual(len(bindings), 4)
        self.assertTrue(all(entry["configuration"]["selection"]["server"] == "uk715.nordvpn.com" for entry in bindings))
        namespace_binding = next(entry for entry in bindings if entry["kind"] == "namespace")
        self.assertEqual(namespace_binding["binding"], self.harness.identity(namespace_binding["identifier"]))

        intents = self.load("operation-intents.json")["operations"]
        self.assertEqual(
            [(operation["outcome"], operation["action"]) for operation in intents],
            [("completed", "create")],
        )

    def test_the_run_record_matches_the_report(self):
        self.restore()
        runs = self.load("startup-runs.json")["runs"]
        self.assertEqual(
            runs,
            [
                {
                    "boot_id": "00000000-0000-0000-0000-000000000001",
                    "recorded_at": "2026-11-02T00:00:00+00:00",
                    "reconciled": True,
                    "restored": ["primary"],
                    "blocked": [],
                    "operator_review_required": False,
                }
            ],
        )


class IdempotentBootTests(RestoreTestBase):
    def test_repeat_restoration_changes_nothing_and_appends_one_record(self):
        first = self.restore()
        second = self.restore(boot_id="00000000-0000-0000-0000-000000000002")
        self.assertEqual(first["restored"], ["primary"])
        self.assertFalse(second["network_changes_applied"])
        self.assertTrue(second["reconciled"])
        self.assertEqual(len(self.load("startup-runs.json")["runs"]), 2)
        self.assertEqual(len(self.load("lifecycle.json")["allocations"]["resources"]), 4)
        self.assertFalse(second["unresolved_intents"])

    def test_decisions_are_deterministic_across_runs(self):
        first = self.restore()
        second = self.restore()
        self.assertEqual(first["decisions"], second["decisions"])


class RebootRestorationTests(RestoreTestBase):
    def test_records_from_a_ended_boot_retire_and_reprovision(self):
        self.restore()
        before = {entry["identifier"] for entry in self.load("owner-bindings.json")["bindings"]}
        self.harness.wipe_kernel()
        report = restore_boot_state(
            self.config,
            kernel=self.harness,
            cleanup_kernel=cleanup_surface(self.harness),
            boot_id="00000000-0000-0000-0000-000000000002",
        )
        self.assertEqual(report["restored"], ["primary"])
        self.assertTrue(report["reconciled"])
        journal = self.load("lifecycle.json")
        states = {event["allocation_id"]: event["state"] for event in journal["events"]}
        self.assertEqual(set(states.values()), {"active", "retired"})
        identifiers = {
            resource["allocation_id"]: resource["identifier"] for resource in journal["allocations"]["resources"]
        }
        self.assertEqual({identifiers[token] for token, state in states.items() if state == "active"} & before, set())

    def test_second_generation_names_differ_from_the_first(self):
        self.restore()
        before = {entry["identifier"] for entry in self.load("owner-bindings.json")["bindings"]}
        self.harness.wipe_kernel()
        restore_boot_state(
            self.config,
            kernel=self.harness,
            cleanup_kernel=cleanup_surface(self.harness),
            boot_id="00000000-0000-0000-0000-000000000003",
        )
        fresh = {
            entry["identifier"]
            for entry in self.load("owner-bindings.json")["bindings"]
            if entry["identifier"] not in before
        }
        self.assertTrue(fresh)
        self.assertFalse(fresh & before)


class FailureInjectionTests(RestoreTestBase):
    def setUp(self):
        super().setUp()

    def test_failed_isolation_install_rolls_back_and_marks_failure_evidence(self):
        def broken(owned, policy):
            raise UnderlayError("nft install failed")

        self.harness.install_isolation = broken
        with self.assertRaises(UnderlayError):
            self.restore()
        intents = self.load("operation-intents.json")["operations"]
        self.assertEqual([operation["outcome"] for operation in intents], ["uncertain"])
        states = {event["allocation_id"]: event["state"] for event in self.load("lifecycle.json")["events"]}
        self.assertEqual(len(states), 4)
        self.assertTrue(all(state == "failed" for state in states.values()))
        # The rollback removed the namespace and its host underlay interface.
        self.assertEqual(self.harness.namespaces, {})
        self.assertEqual(self.harness.host_links, {})
        self.assertEqual(len(self.load("startup-runs.json")["runs"]), 0)


class RefusalTests(RestoreTestBase):
    def test_desired_profile_without_a_pinned_plan_is_reported_not_restored(self):
        self.config["tunnels"] = {}
        report = self.restore()
        self.assertEqual(report["restored"], [])
        self.assertFalse(report["network_changes_applied"])
        self.assertEqual(
            report["profiles_not_restored"],
            [{"profile": "primary", "reason": "the desired profile has no provider tunnel plan"}],
        )

    def test_invalid_plan_refuses_before_any_mutation(self):
        self.config["tunnels"]["primary"]["endpoint_address"] = "not-an-ip"
        with self.assertRaises(RegistryError):
            self.restore()
        with open(self.config["journal"], encoding="utf-8") as source:
            self.assertEqual(json.load(source)["allocations"]["resources"], [])

    def test_plan_without_credential_input_refuses_before_any_mutation(self):
        self.config["credentials"] = {}
        with self.assertRaises(RegistryError):
            self.restore()
        self.assertFalse(Path(self.config["journal"]).exists())
        self.assertFalse(Path(self.config["intent"]).exists())


class DispatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "defaults": {"vpn": "primary"},
                    "vpn_profiles": {
                        "primary": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}
                    },
                    "applications": {},
                }
            ),
            encoding="utf-8",
        )
        self.config_path = self.root / "startup.json"
        self.config_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "policy": str(self.policy_path),
                    "journal": str(self.root / "lifecycle.json"),
                    "bindings": str(self.root / "owner-bindings.json"),
                    "intent": str(self.root / "operation-intents.json"),
                    "run_record": str(self.root / "startup-runs.json"),
                    "tunnels": {},
                    "credentials": {},
                }
            ),
            encoding="utf-8",
        )
        self.env = patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.root / "config")})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_transient_is_never_installed_or_restored(self):
        import contextlib
        import io

        output, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr):
            code = nordvpn_manage.main(["restore-startup", "--config", "/tmp/nonexistent-config.json", "--transient"])
        self.assertEqual(code, 2)
        self.assertIn("transient intent is never restored or installed", stderr.getvalue())
        self.assertEqual(output.getvalue(), "")

    def test_startup_plan_is_read_only_and_renders_the_unit(self):
        import contextlib
        import io
        import json as jsonlib

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = nordvpn_manage.main(
                ["startup-plan", "--config", str(self.config_path), "--unit-dir", str(self.root)]
            )
        self.assertEqual(code, 0)
        result = jsonlib.loads(output.getvalue())
        self.assertEqual(result["executed"], False)
        self.assertEqual(result["mode"], "startup_install_plan")
        self.assertFalse(result["network_changes_applied"])
        self.assertIn("restore-startup", result["unit"])
        self.assertIn("After=network-online.target", result["unit"])
        self.assertFalse((self.root / "nord-tools-restore.service").exists())

    def test_restore_startup_delegates_and_refuses_to_restore_transient(self):
        import contextlib
        import io
        import json as jsonlib

        output = io.StringIO()
        with (
            patch.object(nordvpn_manage, "restore_boot_state", return_value={"restored": []}) as restore,
            contextlib.redirect_stdout(output),
        ):
            code = nordvpn_manage.main(["restore-startup", "--config", str(self.config_path)])
        self.assertEqual(code, 0)
        restore.assert_called_once()
        self.assertEqual(jsonlib.loads(output.getvalue()), {"restored": [], "scope": "persistent"})


if __name__ == "__main__":
    unittest.main()
