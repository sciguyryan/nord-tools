"""Offline application reference lifecycle tests."""

import unittest

from nord_tools_internal.nordvpn_application_binding import ApplicationBindingState, plan_binding, plan_unbinding
from nord_tools_internal.nordvpn_application_plan import plan_application
from nord_tools_internal.nordvpn_profiles import ProfileError
from tests.test_application_plan import POLICY


class ApplicationBindingTests(unittest.TestCase):
    def test_shared_allocation_references_and_last_release(self):
        state = ApplicationBindingState()
        first = plan_binding(state, plan_application(POLICY, "browser"))
        second = plan_binding(first.state, plan_application(POLICY, "editor"))
        self.assertEqual((first.allocation_users_before, first.allocation_users_after), (0, 1))
        self.assertEqual((second.allocation_users_before, second.allocation_users_after), (1, 2))
        removed = plan_unbinding(second.state, "browser")
        self.assertEqual(removed.allocation_users_after, 1)
        self.assertEqual(plan_unbinding(removed.state, "editor").allocation_users_after, 0)
        self.assertEqual(state.bindings, ())

    def test_isolated_allocations_remain_distinct(self):
        first = plan_binding(ApplicationBindingState(), plan_application(POLICY, "private1"))
        second = plan_binding(first.state, plan_application(POLICY, "private2"))
        self.assertNotEqual(first.allocation_key, second.allocation_key)
        self.assertEqual(second.allocation_users_before, 0)

    def test_reuse_and_conflicting_rebind(self):
        first = plan_binding(ApplicationBindingState(), plan_application(POLICY, "browser"))
        reused = plan_binding(first.state, plan_application(POLICY, "browser"))
        self.assertEqual(reused.action, "reuse")
        self.assertEqual(reused.state, first.state)
        with self.assertRaises(ProfileError):
            plan_binding(first.state, plan_application(POLICY, "browser", ("--changed",)))

    def test_unknown_release_and_duplicate_state_rejected(self):
        first = plan_binding(ApplicationBindingState(), plan_application(POLICY, "browser"))
        with self.assertRaises(ProfileError):
            plan_unbinding(first.state, "unknown")
        with self.assertRaises(ProfileError):
            plan_binding(ApplicationBindingState((first.state.bindings[0],) * 2), plan_application(POLICY, "editor"))
