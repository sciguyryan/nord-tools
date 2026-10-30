"""Deterministic offline application routing consistency checks."""

import unittest
from dataclasses import replace

from nord_tools_internal.nordvpn_application_audit import audit_application_state
from nord_tools_internal.nordvpn_application_binding import ApplicationBindingState, plan_binding
from nord_tools_internal.nordvpn_application_launch import prepare_application_launch
from nord_tools_internal.nordvpn_application_plan import plan_application
from nord_tools_internal.nordvpn_application_session import ApplicationSessionState, plan_session_start
from nord_tools_internal.nordvpn_profiles import ProfileError
from tests.test_application_plan import POLICY


class ApplicationAuditTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_application(POLICY, "browser")
        self.bindings = plan_binding(ApplicationBindingState(), self.plan).state
        self.request = prepare_application_launch(self.bindings, self.plan)
        self.sessions = plan_session_start(ApplicationSessionState(), self.bindings, self.request, "session").state

    def test_consistent_state_is_descriptive_not_authoritative(self):
        report = audit_application_state(self.bindings, self.sessions)
        self.assertEqual((report.binding_count, report.session_count), (1, 1))
        self.assertFalse(report.production_authorised)
        self.assertEqual(report.allocations[0].session_count, 1)

    def test_orphan_session_is_rejected(self):
        with self.assertRaisesRegex(ProfileError, "matching current binding"):
            audit_application_state(ApplicationBindingState(), self.sessions)

    def test_stale_session_command_is_rejected(self):
        altered = replace(self.bindings.bindings[0], arguments=("--changed",))
        with self.assertRaisesRegex(ProfileError, "matching current binding"):
            audit_application_state(ApplicationBindingState((altered,)), self.sessions)

    def test_cross_profile_allocation_collision_is_rejected(self):
        other = replace(self.bindings.bindings[0], application="other", profile="different")
        with self.assertRaisesRegex(ProfileError, "different profiles"):
            audit_application_state(
                ApplicationBindingState((*self.bindings.bindings, other)), ApplicationSessionState()
            )

    def test_order_independent_allocation_summaries(self):
        other = replace(self.bindings.bindings[0], application="other", allocation_key="aaa")
        forward = ApplicationBindingState((*self.bindings.bindings, other))
        backward = ApplicationBindingState(tuple(reversed(forward.bindings)))
        self.assertEqual(
            audit_application_state(forward, ApplicationSessionState()),
            audit_application_state(backward, ApplicationSessionState()),
        )

    def test_malformed_state_is_rejected(self):
        with self.assertRaises(ProfileError):
            audit_application_state(None, self.sessions)
