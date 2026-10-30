"""Offline application launch boundary and denial tests."""

import unittest

from nord_tools_internal.nordvpn_application_binding import ApplicationBindingState, plan_binding
from nord_tools_internal.nordvpn_application_launch import execute_application_launch, prepare_application_launch
from nord_tools_internal.nordvpn_application_plan import plan_application
from nord_tools_internal.nordvpn_profiles import ProfileError
from tests.test_application_plan import POLICY


class ApplicationLaunchTests(unittest.TestCase):
    def test_exact_binding_prepares_argv_without_authority(self):
        plan = plan_application(POLICY, "browser", ("--new-window", "a b"))
        state = plan_binding(ApplicationBindingState(), plan).state
        request = prepare_application_launch(state, plan)
        self.assertEqual(request.argv, ("/usr/bin/browser", "--new-window", "a b"))
        self.assertFalse(request.namespace_authorised)
        with self.assertRaises(ProfileError):
            execute_application_launch(request)

    def test_unbound_and_stale_requests_are_rejected(self):
        plan = plan_application(POLICY, "browser")
        with self.assertRaises(ProfileError):
            prepare_application_launch(ApplicationBindingState(), plan)
        state = plan_binding(ApplicationBindingState(), plan).state
        with self.assertRaises(ProfileError):
            prepare_application_launch(state, plan_application(POLICY, "browser", ("--other",)))
        with self.assertRaises(ProfileError):
            prepare_application_launch(state, plan_application(POLICY, "editor"))

    def test_reject_invalid_request(self):
        with self.assertRaises(ProfileError):
            execute_application_launch(None)

    def test_request_is_immutable(self):
        plan = plan_application(POLICY, "private1")
        request = prepare_application_launch(plan_binding(ApplicationBindingState(), plan).state, plan)
        with self.assertRaises(AttributeError):
            request.namespace_authorised = True
