"""Offline resolver policy validation and deterministic rendering tests."""

import unittest

from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy, ResolverPolicyError


class ResolverPolicyTests(unittest.TestCase):
    def test_render_dual_stack(self):
        policy = NamespaceResolverPolicy(("1.1.1.1", "2606:4700:4700::1111"))
        self.assertEqual(
            policy.render_resolv_conf(),
            "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\noptions attempts:1 timeout:2\n",
        )
        self.assertFalse(policy.public_plan()["dns_confined"])
        self.assertFalse(policy.public_plan()["resolver_configuration_applied"])

    def test_canonicalise_numeric_addresses(self):
        self.assertEqual(NamespaceResolverPolicy(("2001:4860:4860:0:0:0:0:8888",)).servers, ("2001:4860:4860::8888",))

    def test_reject_empty_and_excessive_servers(self):
        for servers in ((), ("1.1.1.1",) * 4, ["1.1.1.1"]):
            with self.subTest(servers=servers), self.assertRaises(ResolverPolicyError):
                NamespaceResolverPolicy(servers)

    def test_reject_hostname_and_injection(self):
        for server in ("dns.example", "1.1.1.1\noptions rotate", "1.1.1.1 # comment", "", "[::1]", 123):
            with self.subTest(server=server), self.assertRaises(ResolverPolicyError):
                NamespaceResolverPolicy((server,))

    def test_reject_non_tunnel_resolver_candidates(self):
        for server in ("127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "fe80::1", "169.254.1.1"):
            with self.subTest(server=server), self.assertRaises(ResolverPolicyError):
                NamespaceResolverPolicy((server,))

    def test_reject_duplicates_after_normalisation(self):
        with self.assertRaises(ResolverPolicyError):
            NamespaceResolverPolicy(("2001:4860:4860::8888", "2001:4860:4860:0:0:0:0:8888"))

    def test_input_tuple_not_mutated(self):
        servers = ("1.1.1.1",)
        policy = NamespaceResolverPolicy(servers)
        self.assertEqual(servers, policy.servers)
        self.assertEqual(policy.render_resolv_conf(), policy.render_resolv_conf())


if __name__ == "__main__":
    unittest.main()
