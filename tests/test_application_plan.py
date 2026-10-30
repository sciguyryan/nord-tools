"""Per-application routing decisions are deterministic and side-effect free."""

import copy
import unittest

from nord_tools_internal.nordvpn_application_plan import plan_application
from nord_tools_internal.nordvpn_profiles import ProfileError

POLICY = {
    "version": 1,
    "defaults": {"vpn": "default"},
    "vpn_profiles": {
        "default": {"selection": {"mode": "country", "country": "GB"}},
        "private": {"selection": {"mode": "country", "country": "DE"}, "sharing": "isolated"},
    },
    "applications": {
        "browser": {"executable": "/usr/bin/browser"},
        "editor": {"executable": "/usr/bin/editor", "vpn": "default"},
        "private1": {"executable": "/usr/bin/private1", "vpn": "private"},
        "private2": {"executable": "/usr/bin/private2", "vpn": "private"},
    },
}


class ApplicationPlanTests(unittest.TestCase):
    def test_default_inheritance_and_explicit_shared_reuse(self):
        original = copy.deepcopy(POLICY)
        browser = plan_application(POLICY, "browser", ("--new-window",))
        editor = plan_application(POLICY, "editor")
        self.assertTrue(browser.inherited)
        self.assertFalse(editor.inherited)
        self.assertEqual(browser.allocation_key, editor.allocation_key)
        self.assertEqual(browser.arguments, ("--new-window",))
        self.assertEqual(POLICY, original)

    def test_isolated_applications_do_not_share_allocation(self):
        first = plan_application(POLICY, "private1")
        second = plan_application(POLICY, "private2")
        self.assertNotEqual(first.allocation_key, second.allocation_key)
        self.assertEqual(first.sharing, "isolated")

    def test_unregistered_or_malformed_inputs_fail_closed(self):
        for name, args in (("unknown", ()), ("../browser", ()), ("browser", ["x"]), ("browser", ("x\x00y",))):
            with self.subTest(name=name, args=args), self.assertRaises(ProfileError):
                plan_application(POLICY, name, args)

    def test_immutable_plan(self):
        plan = plan_application(POLICY, "browser")
        with self.assertRaises(AttributeError):
            plan.profile = "private"
