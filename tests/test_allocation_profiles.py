"""Isolation must have distinct journal identities, not merely distinct keys."""

import json
from copy import deepcopy

from nord_tools_internal.nordvpn_allocation_profiles import (
    expand_allocation_profiles,
    kernel_profile_for_allocation,
)
from test_restore_executor import RestoreTestBase


class AllocationProfileTests(RestoreTestBase):
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
