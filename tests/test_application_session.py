"""Offline session lifecycle and namespace requirements."""

import unittest

from nord_tools_internal.nordvpn_application_binding import ApplicationBindingState, plan_binding
from nord_tools_internal.nordvpn_application_launch import prepare_application_launch
from nord_tools_internal.nordvpn_application_plan import plan_application
from nord_tools_internal.nordvpn_application_session import (
    ApplicationSessionState,
    application_namespace_requirements,
    plan_session_start,
    plan_session_stop,
)
from nord_tools_internal.nordvpn_profiles import ProfileError
from tests.test_application_plan import POLICY


class ApplicationSessionTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_application(POLICY, "browser")
        self.bindings = plan_binding(ApplicationBindingState(), self.plan).state
        self.request = prepare_application_launch(self.bindings, self.plan)

    def test_start_reuse_and_stop_are_logical_only(self):
        first = plan_session_start(ApplicationSessionState(), self.bindings, self.request, "one")
        self.assertEqual((first.action, first.allocation_users_before, first.allocation_users_after), ("start", 0, 1))
        again = plan_session_start(first.state, self.bindings, self.request, "one")
        self.assertEqual((again.action, again.allocation_users_before, again.allocation_users_after), ("reuse", 1, 1))
        second = plan_session_start(first.state, self.bindings, self.request, "two")
        self.assertEqual(second.allocation_users_after, 2)
        stopped = plan_session_stop(second.state, "one")
        self.assertEqual((stopped.allocation_users_before, stopped.allocation_users_after), (2, 1))
        self.assertEqual(len(stopped.state.sessions), 1)

    def test_stale_binding_and_duplicate_identifier_fail_closed(self):
        with self.assertRaises(ProfileError):
            plan_session_start(ApplicationSessionState(), ApplicationBindingState(), self.request, "one")
        first = plan_session_start(ApplicationSessionState(), self.bindings, self.request, "one")
        other_plan = plan_application(POLICY, "editor")
        other_bindings = plan_binding(self.bindings, other_plan).state
        other_request = prepare_application_launch(other_bindings, other_plan)
        with self.assertRaises(ProfileError):
            plan_session_start(first.state, other_bindings, other_request, "one")
        with self.assertRaises(ProfileError):
            plan_session_stop(first.state, "missing")

    def test_reject_invalid_identifiers_and_forged_authority(self):
        for identifier in ("", "bad\x00id", None):
            with self.subTest(identifier=identifier), self.assertRaises(ProfileError):
                plan_session_start(ApplicationSessionState(), self.bindings, self.request, identifier)
        from dataclasses import replace

        with self.assertRaises(ProfileError):
            plan_session_start(
                ApplicationSessionState(), self.bindings, replace(self.request, namespace_authorised=True), "one"
            )

    def test_namespace_requirements_are_explicit_not_claimed_as_verified(self):
        requirements = application_namespace_requirements()
        self.assertTrue(any("Wayland" in item for item in requirements))
        self.assertTrue(any("IPv6" in item for item in requirements))
        self.assertTrue(any("ownership" in item for item in requirements))
