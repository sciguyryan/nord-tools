"""Routing policy validation must not alter configuration or networking."""

import copy
import unittest

from nord_tools_internal.nordvpn_profiles import (
    ProfileError,
    resolve_application,
    resolve_named_profiles,
    validate_policy,
)


POLICY = {
    "version": 1,
    "defaults": {"vpn": "primary"},
    "vpn_profiles": {
        "primary": {"selection": {"mode": "fastest", "filter": "country:ad&protocol:udp"}},
        "discord": {"selection": {"mode": "country", "country": "GB"}},
        "fixed": {"selection": {"mode": "pinned", "server": "gb123"}, "sharing": "isolated"},
    },
    "applications": {"discord": {"executable": "/usr/bin/discord", "vpn": "discord"}},
}


class ProfileTests(unittest.TestCase):
    def test_normalisation_does_not_mutate_input(self):
        source = copy.deepcopy(POLICY)
        checked = validate_policy(source)
        self.assertEqual(source, POLICY)
        self.assertEqual(checked["vpn_profiles"]["discord"]["selection"]["country"], "gb")
        self.assertEqual(checked["vpn_profiles"]["fixed"]["selection"]["server"], "gb123.nordvpn.com")

    def test_default_and_explicit_override(self):
        self.assertEqual(
            resolve_application(POLICY, "unlisted"), {"application": "unlisted", "vpn": "primary", "inherited": True}
        )
        self.assertEqual(
            resolve_application(POLICY, "discord"), {"application": "discord", "vpn": "discord", "inherited": False}
        )

    def test_invalid_policy_variants(self):
        variants = [
            ("version", 2),
            ("defaults", {"vpn": "missing"}),
            ("applications", {"discord": {"executable": "discord", "vpn": "discord"}}),
            ("applications", {"discord": {"executable": "/usr/bin/discord", "vpn": "missing"}}),
            ("vpn_profiles", {"primary": {"selection": {"mode": "country", "country": "AND"}}}),
            ("vpn_profiles", {"primary": {"selection": {"mode": "pinned", "server": "not-a-server"}}}),
            ("vpn_profiles", {"primary": {"selection": {"mode": "fastest", "filter": "country:"}}}),
            (
                "vpn_profiles",
                {"primary": {"selection": {"mode": "fastest", "filter": "ad", "minimum_improvement_ms": True}}},
            ),
            (
                "vpn_profiles",
                {"primary": {"selection": {"mode": "fastest", "filter": "ad", "minimum_improvement_percent": 101}}},
            ),
            ("vpn_profiles", {"primary": {"selection": {"mode": "country", "country": "AD"}, "sharing": "isolated"}}),
        ]
        for key, value in variants:
            with self.subTest(key=key, value=value):
                policy = copy.deepcopy(POLICY)
                policy[key] = value
                with self.assertRaises(ProfileError):
                    validate_policy(policy)

    def test_named_profile_resolution_is_deterministic_and_detached(self):
        original = copy.deepcopy(POLICY)
        first = resolve_named_profiles(original, ["fixed", "primary"])
        second = resolve_named_profiles(original, ["primary", "fixed"])
        self.assertEqual(first, second)
        self.assertEqual([entry["name"] for entry in first], ["fixed", "primary"])
        self.assertEqual([entry["default"] for entry in first], [False, True])
        first[0]["profile"]["sharing"] = "shared"
        self.assertEqual(original, POLICY)
        self.assertEqual([entry["name"] for entry in resolve_named_profiles(original)], ["discord", "fixed", "primary"])
        self.assertEqual(resolve_named_profiles(original, []), ())

    def test_named_profile_resolution_rejects_ambiguity(self):
        for requested in (
            "primary",
            b"primary",
            {"primary"},
            ["primary", "primary"],
            ["missing"],
            [None],
            [1],
            ["primary", "missing"],
        ):
            with self.subTest(requested=requested), self.assertRaises(ProfileError):
                resolve_named_profiles(POLICY, requested)

    def test_unknown_fields_rejected(self):
        policy = copy.deepcopy(POLICY)
        policy["applications"]["discord"]["root_command"] = "echo unsafe"
        with self.assertRaises(ProfileError):
            validate_policy(policy)


if __name__ == "__main__":
    unittest.main()
