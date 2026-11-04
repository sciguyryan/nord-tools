"""Conservative consumer reference planning tests."""

import copy
import unittest

from nord_tools_internal.nordvpn_profiles import ProfileError
from nord_tools_internal.nordvpn_sharing_lifecycle import plan_consumer_release
from tests.test_application_plan import POLICY


class SharingLifecycleTests(unittest.TestCase):
    def test_one_shared_consumer_cannot_release_the_group(self):
        decisions = plan_consumer_release(POLICY, ("browser",))
        shared = next(item for item in decisions if item.allocation_key == "profile:default")
        self.assertEqual(shared.released_consumers, ("browser",))
        self.assertEqual(shared.retained_consumers, ("editor",))
        self.assertFalse(shared.retirement_eligible)

    def test_last_shared_consumer_allows_only_consideration(self):
        shared = next(
            item
            for item in plan_consumer_release(POLICY, ("editor", "browser"))
            if item.allocation_key == "profile:default"
        )
        self.assertTrue(shared.retirement_eligible)
        self.assertEqual(shared.retained_consumers, ())

    def test_isolated_consumer_release_preserves_other_allocation(self):
        decisions = plan_consumer_release(POLICY, ("private1",))
        isolated = {item.allocation_key: item for item in decisions if item.sharing == "isolated"}
        self.assertEqual(len(isolated), 2)
        self.assertEqual(sum(item.retirement_eligible for item in isolated.values()), 1)

    def test_empty_release_retains_every_reference(self):
        self.assertTrue(all(not item.retirement_eligible for item in plan_consumer_release(POLICY, ())))

    def test_invalid_releases_are_rejected_without_policy_mutation(self):
        original = copy.deepcopy(POLICY)
        for invalid in (("browser", "browser"), ("missing",), ["browser"], (1,)):
            with self.subTest(invalid=invalid), self.assertRaises(ProfileError):
                plan_consumer_release(POLICY, invalid)
        self.assertEqual(POLICY, original)

    def test_deterministic_and_immutable(self):
        first = plan_consumer_release(POLICY, ("private2", "browser"))
        self.assertEqual(first, plan_consumer_release(POLICY, ("browser", "private2")))
        with self.assertRaises(AttributeError):
            first[0].retirement_eligible = False
