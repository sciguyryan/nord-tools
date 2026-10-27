"""Tests for conservative offline namespace firewall rendering."""

import unittest

from nord_tools_internal.nordvpn_failclosed_policy import IsolationPolicyError, NamespaceIsolationPolicy


class IsolationPolicyTests(unittest.TestCase):
    def policy(self, **changes):
        args = {
            "tunnel_interface": "ntwg1234",
            "underlay_interface": "veth0",
            "endpoint_address": "198.51.100.20",
            "endpoint_port": 51820,
        }
        args.update(changes)
        return NamespaceIsolationPolicy(**args)

    def test_default_drop_both_families_and_forward(self):
        rules = self.policy().render_nft()
        self.assertEqual(rules.count("policy drop;"), 3)
        self.assertIn("table inet nord_tools_isolation", rules)
        self.assertNotIn("flush ruleset", rules)

    def test_only_specific_underlay_udp_endpoint(self):
        rules = self.policy().render_nft()
        self.assertIn('oifname "veth0" ip daddr 198.51.100.20 udp dport 51820 accept', rules)
        self.assertNotIn("udp dport 53 accept", rules)

    def test_ipv6_endpoint_is_family_scoped(self):
        rules = self.policy(endpoint_address="2001:db8::2").render_nft()
        self.assertIn("ip6 daddr 2001:db8::2 udp dport 51820 accept", rules)

    def test_untrusted_interface_names_rejected(self):
        for name in ('bad" accept', "too_long_interface_name", "", "a b", "eth0\n"):
            with self.subTest(name=name), self.assertRaises(IsolationPolicyError):
                self.policy(underlay_interface=name)

    def test_same_interface_rejected(self):
        with self.assertRaises(IsolationPolicyError):
            self.policy(underlay_interface="ntwg1234")

    def test_invalid_endpoints_and_ports_rejected(self):
        for address in ("example.com", "127.0.0.1", "::", "ff02::1", "fe80::1"):
            with self.subTest(address=address), self.assertRaises(IsolationPolicyError):
                self.policy(endpoint_address=address)
        for port in (0, 65536, True, "51820"):
            with self.subTest(port=port), self.assertRaises(IsolationPolicyError):
                self.policy(endpoint_port=port)

    def test_plan_explicitly_non_authoritative(self):
        plan = self.policy().public_plan()
        self.assertFalse(plan["network_changes_applied"])
        self.assertFalse(plan["firewall_installed"])
        self.assertFalse(plan["dns_confined"])
        self.assertTrue(plan["requires_atomic_pretraffic_installation"])

    def test_deterministic_rendering(self):
        self.assertEqual(self.policy().render_nft(), self.policy().render_nft())


if __name__ == "__main__":
    unittest.main()
