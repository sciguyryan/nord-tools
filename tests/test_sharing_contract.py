"""Offline sharing boundaries do not grant resource lifecycle authority."""

import copy
import unittest

from nord_tools_internal.nordvpn_profiles import ProfileError
from nord_tools_internal.nordvpn_sharing_contract import resolve_ownership_groups
from tests.test_application_plan import POLICY


class SharingContractTests(unittest.TestCase):
    def test_shared_consumers_reuse_one_logical_group(self):
        groups = resolve_ownership_groups(POLICY)
        shared = [group for group in groups if group.profile == "default"]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0].consumers, ("browser", "editor"))
        self.assertEqual(shared[0].allocation_key, "profile:default")

    def test_isolated_consumers_never_reuse_group(self):
        groups = resolve_ownership_groups(POLICY)
        isolated = [group for group in groups if group.profile == "private"]
        self.assertEqual(len(isolated), 2)
        self.assertEqual({group.consumers for group in isolated}, {("private1",), ("private2",)})
        self.assertEqual(len({group.allocation_key for group in groups}), len(groups))

    def test_deterministic_detached_and_immutable(self):
        original = copy.deepcopy(POLICY)
        groups = resolve_ownership_groups(POLICY)
        self.assertEqual(groups, resolve_ownership_groups(POLICY))
        self.assertEqual(POLICY, original)
        with self.assertRaises(AttributeError):
            groups[0].sharing = "isolated"
        changed = copy.deepcopy(POLICY)
        changed["applications"]["browser"]["executable"] = "/usr/bin/changed"
        self.assertEqual(groups, resolve_ownership_groups(changed))

    def test_unused_profile_does_not_create_consumer(self):
        policy = copy.deepcopy(POLICY)
        policy["vpn_profiles"]["unused"] = {"selection": {"mode": "country", "country": "FR"}}
        self.assertNotIn("unused", {group.profile for group in resolve_ownership_groups(policy)})

    def test_invalid_policy_is_rejected(self):
        policy = copy.deepcopy(POLICY)
        policy["applications"]["browser"]["vpn"] = "missing"
        with self.assertRaises(ProfileError):
            resolve_ownership_groups(policy)
