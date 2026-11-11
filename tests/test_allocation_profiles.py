"""Isolation must have distinct journal identities, not merely distinct keys."""

import json
from copy import deepcopy
import datetime
import os

from nord_tools_internal.nordvpn_allocation_profiles import (
    expand_allocation_profiles,
    kernel_profile_for_allocation,
)
from test_restore_executor import RestoreTestBase, _KEY


class AllocationProfileTests(RestoreTestBase):
    def test_provider_backed_default_shared_and_isolated_workflow(self):
        policy = {
            "version": 1,
            "defaults": {"vpn": "primary"},
            "vpn_profiles": {
                "primary": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"},
                "shared": {"selection": {"mode": "country", "country": "gb"}, "sharing": "shared"},
                "isolated": {
                    "selection": {"mode": "fastest", "filter": "country:gb&protocol:udp"},
                    "sharing": "isolated",
                },
            },
            "applications": {
                "alpha": {"executable": "/bin/true", "vpn": "isolated"},
                "beta": {"executable": "/bin/false", "vpn": "isolated"},
            },
        }
        self.policy_path.write_text(json.dumps(policy), encoding="utf-8")
        servers = []
        for index, server in enumerate(
            ("uk715.nordvpn.com", "gb123.nordvpn.com", "gb124.nordvpn.com", "gb125.nordvpn.com"), start=1
        ):
            credential = self.root / f"{server}.key"
            credential.write_text(_KEY + "\n", encoding="ascii")
            credential.chmod(0o600)
            servers.append(
                {
                    "server": server,
                    "country": "gb",
                    "peer_public_key": _KEY,
                    "client_public_key": _KEY,
                    "endpoint_address": f"198.51.100.{index}",
                    "endpoint_port": 51820,
                    "persistent_keepalive_seconds": 25,
                    "tunnel_addresses": ["10.5.0.2/32", "fd42:5::2/128"],
                    "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
                    "dns_servers": ["10.5.0.1", "fd42:5::1"],
                    "credential": str(credential),
                }
            )
        catalogue = self.root / "provider-catalogue.json"
        catalogue.write_text(json.dumps({"version": 1, "provider": "nordvpn", "servers": servers}))
        catalogue.chmod(0o600)
        benchmark = self.root / "benchmark.json"
        benchmark.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "ranking": [
                        {
                            "server": "gb124.nordvpn.com",
                            "protocol": "udp",
                            "port": 51820,
                            "received": 3,
                            "loss_pct": 0,
                            "median_ms": 4,
                        },
                        {
                            "server": "gb123.nordvpn.com",
                            "protocol": "udp",
                            "port": 51820,
                            "received": 3,
                            "loss_pct": 0,
                            "median_ms": 8,
                        },
                        {
                            "server": "gb125.nordvpn.com",
                            "protocol": "udp",
                            "port": 51820,
                            "received": 3,
                            "loss_pct": 0,
                            "median_ms": 6,
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        effective, sources = expand_allocation_profiles(policy)
        self.config["provider"] = {
            "catalogue": str(catalogue),
            "benchmark_report": str(benchmark),
            "max_report_age_seconds": 60,
        }
        self.config["credentials"] = {}
        self.config["tunnels"] = {}
        for index, name in enumerate(sorted(effective["vpn_profiles"]), start=1):
            self.config["tunnels"][name] = {
                "underlay": {
                    "namespace_address": f"10.216.{index}.2/30",
                    "host_address": f"10.216.{index}.1/30",
                }
            }
        self.harness.public_key_from_fd = lambda fd: _KEY if os.read(fd, 46).strip() else ""
        self.harness.verify_wireguard = lambda *args, **kwargs: True
        self.harness.install_resolver = lambda namespace, dns_policy: (namespace, dns_policy)
        self.harness.verify_dns = lambda namespace, interface, dns_policy: True
        self.harness.remove_resolver = lambda installation: None
        report = self.restore()
        self.assertEqual(set(report["restored"]), set(effective["vpn_profiles"]))
        self.assertEqual(
            {name: value["server"] for name, value in report["provider_selections"].items()},
            {
                "primary": "uk715.nordvpn.com",
                "shared": "gb123.nordvpn.com",
                **{
                    name: server
                    for name, server in zip(
                        sorted(name for name, source in sources.items() if source == "isolated"),
                        ("gb124.nordvpn.com", "gb125.nordvpn.com"),
                        strict=True,
                    )
                },
            },
        )
        self.assertEqual(len(self.harness.namespaces), 4)
        self.assertEqual(self.restore()["restored"], [])

    def test_isolated_consumers_get_independent_production_resources(self):
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["vpn_profiles"]["isolated"] = {
            "selection": {"mode": "pinned", "server": "uk716"},
            "sharing": "isolated",
        }
        policy["applications"] = {
            "alpha": {"executable": "/bin/true", "vpn": "isolated"},
            "beta": {"executable": "/bin/false", "vpn": "isolated"},
        }
        self.policy_path.write_text(json.dumps(policy), encoding="utf-8")
        self.config["tunnels"]["isolated"] = deepcopy(self.config["tunnels"]["primary"])
        self.config["credentials"]["isolated"] = str(self.credential_path)
        effective, sources = expand_allocation_profiles(policy)
        expected = {
            kernel_profile_for_allocation(f"application:{app}:profile:isolated", "isolated", "isolated")
            for app in ("alpha", "beta")
        }
        self.assertEqual(set(sources), {"primary", *expected})
        self.assertNotIn("isolated", effective["vpn_profiles"])
        for index, identity in enumerate(sorted(expected), start=1):
            plan = deepcopy(self.config["tunnels"]["isolated"])
            plan["underlay"] = {
                "namespace_address": f"10.215.{index}.2/30",
                "host_address": f"10.215.{index}.1/30",
            }
            self.config["tunnels"][identity] = plan
        result = self.restore()
        self.assertEqual(set(result["restored"]), {"primary", *expected})
        self.assertEqual(len(self.harness.namespaces), 3)
        self.assertEqual(len(self.load("owner-bindings.json")["bindings"]), 12)
        self.assertEqual(
            {item["profile"] for item in self.load("lifecycle.json")["allocations"]["resources"]},
            {"primary", *expected},
        )
        second = self.restore()
        self.assertEqual(second["restored"], [])
        self.assertTrue(second["reconciled"])

    def test_provisioned_acquisition_requires_verified_allocation(self):
        import os
        from unittest.mock import patch
        from nord_tools_internal.nordvpn_runtime_consumers import (
            acquire_provisioned_consumer,
            initialise_runtime_consumers,
            read_runtime_consumers,
        )
        from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError

        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["applications"] = {"alpha": {"executable": "/bin/true", "vpn": "primary"}}
        self.policy_path.write_text(json.dumps(policy), encoding="utf-8")
        store = self.root / "runtime.json"
        initialise_runtime_consumers(store, policy)
        kwargs = {
            "journal_path": self.config["journal"],
            "bindings_path": self.config["bindings"],
            "intent_path": self.config["intent"],
            "observe": self.harness.observe,
        }
        with (
            patch("nord_tools_internal.nordvpn_runtime_consumers._identity", return_value=("boot", "123", "/bin/true")),
            self.assertRaisesRegex(ConsumerReferenceError, "cannot read"),
        ):
            acquire_provisioned_consumer(store, policy, "alpha", os.getpid(), **kwargs)
        self.restore()
        with patch(
            "nord_tools_internal.nordvpn_runtime_consumers._identity", return_value=("boot", "123", "/bin/true")
        ):
            result = acquire_provisioned_consumer(store, policy, "alpha", os.getpid(), **kwargs)
        self.assertEqual(len(result["leases"]), 1)
        self.assertEqual(read_runtime_consumers(store, policy)["leases"][0]["allocation_key"], "profile:primary")

    def test_staged_launch_requires_verified_namespace_and_records_expected_executable(self):
        import os
        from unittest.mock import patch
        from types import SimpleNamespace

        original_stat = os.stat

        def namespace_stat(path, *args, mismatch=False, **kwargs):
            if str(path).startswith("/run/netns/"):
                return SimpleNamespace(st_dev=1, st_ino=2)
            if str(path).startswith("/proc/") and str(path).endswith("/ns/net"):
                return SimpleNamespace(st_dev=1, st_ino=3 if mismatch else 2)
            return original_stat(path, *args, **kwargs)

        from nord_tools_internal.nordvpn_runtime_consumers import (
            reserve_staged_consumer,
            initialise_runtime_consumers,
            read_runtime_consumers,
        )
        from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError

        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["applications"] = {"alpha": {"executable": "/bin/true", "vpn": "primary"}}
        self.policy_path.write_text(json.dumps(policy), encoding="utf-8")
        store = self.root / "runtime.json"
        initialise_runtime_consumers(store, policy)
        self.restore()
        journal = self.load("lifecycle.json")
        namespace = next(
            item["identifier"] for item in journal["allocations"]["resources"] if item["kind"] == "namespace"
        )
        kwargs = {
            "journal_path": self.config["journal"],
            "bindings_path": self.config["bindings"],
            "intent_path": self.config["intent"],
            "observe": self.harness.observe,
            "staging_executable": "/usr/bin/python",
            "namespace": namespace,
        }
        with (
            patch(
                "nord_tools_internal.nordvpn_runtime_consumers.os.stat",
                side_effect=lambda path, *a, **kw: namespace_stat(path, *a, mismatch=True, **kw),
            ),
            self.assertRaisesRegex(ConsumerReferenceError, "outside the verified namespace"),
        ):
            reserve_staged_consumer(store, policy, "alpha", os.getpid(), **kwargs)
        with (
            patch("nord_tools_internal.nordvpn_runtime_consumers.os.stat", side_effect=namespace_stat),
            patch(
                "nord_tools_internal.nordvpn_runtime_consumers._identity",
                return_value=("boot", "123", "/usr/bin/python"),
            ),
        ):
            reserve_staged_consumer(store, policy, "alpha", os.getpid(), **kwargs)
        self.assertEqual(read_runtime_consumers(store, policy)["leases"][0]["executable"], "/bin/true")

    def test_selected_isolated_retirement_preserves_other_consumer(self):
        import os
        from unittest.mock import patch
        from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup
        from nord_tools_internal.nordvpn_registry import RegistryError
        from nord_tools_internal.nordvpn_runtime_consumers import (
            acquire_provisioned_consumer,
            initialise_runtime_consumers,
        )
        from test_restore_executor import cleanup_surface

        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["vpn_profiles"]["isolated"] = {
            "selection": {"mode": "pinned", "server": "uk716"},
            "sharing": "isolated",
        }
        policy["applications"] = {
            "alpha": {"executable": "/bin/true", "vpn": "isolated"},
            "beta": {"executable": "/bin/false", "vpn": "isolated"},
        }
        self.policy_path.write_text(json.dumps(policy), encoding="utf-8")
        isolated = deepcopy(self.config["tunnels"]["primary"])
        for index, application in enumerate(("alpha", "beta"), start=1):
            key = f"application:{application}:profile:isolated"
            identity = kernel_profile_for_allocation(key, "isolated", "isolated")
            plan = deepcopy(isolated)
            plan["underlay"] = {
                "namespace_address": f"10.215.{index}.2/30",
                "host_address": f"10.215.{index}.1/30",
            }
            self.config["tunnels"][identity] = plan
        self.config["credentials"]["isolated"] = str(self.credential_path)
        self.restore()
        store = self.root / "runtime.json"
        initialise_runtime_consumers(store, policy)
        with patch(
            "nord_tools_internal.nordvpn_runtime_consumers._identity", return_value=("boot", "123", "/bin/false")
        ):
            acquire_provisioned_consumer(
                store,
                policy,
                "beta",
                os.getpid(),
                journal_path=self.config["journal"],
                bindings_path=self.config["bindings"],
                intent_path=self.config["intent"],
                observe=self.harness.observe,
            )
        alpha = kernel_profile_for_allocation("application:alpha:profile:isolated", "isolated", "isolated")
        beta = kernel_profile_for_allocation("application:beta:profile:isolated", "isolated", "isolated")
        common = {
            "intent_path": self.config["intent"],
            "consumer_policy": policy,
            "released_consumers": ("alpha",),
            "runtime_consumers_path": store,
            "selected_profiles": (alpha,),
            "kernel": cleanup_surface(self.harness),
        }
        report = plan_cleanup(self.config["journal"], self.config["bindings"], **common)
        self.assertEqual({entry["profile"] for entry in report["plan"]}, {alpha})
        self.assertIn(beta, {entry["profile"] for entry in report["preserved"]})
        with self.assertRaisesRegex(RegistryError, "runtime consumer leases"):
            plan_cleanup(
                self.config["journal"],
                self.config["bindings"],
                **{**common, "selected_profiles": (beta,), "released_consumers": ("beta",)},
            )

    def test_isolated_retirement_without_runtime_store_refused(self):
        from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup
        from nord_tools_internal.nordvpn_registry import RegistryError

        identity = kernel_profile_for_allocation("application:alpha:profile:isolated", "isolated", "isolated")
        with self.assertRaisesRegex(RegistryError, "requires runtime consumer evidence"):
            plan_cleanup(
                self.config["journal"],
                self.config["bindings"],
                selected_profiles=(identity,),
            )
