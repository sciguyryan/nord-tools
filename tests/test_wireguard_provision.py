"""Adversarial offline checks for the provisioning input boundary."""

import base64
import unittest

from nord_tools_internal.nordvpn_wireguard_provision import ProvisioningError, TunnelSpecification


class TunnelSpecificationTests(unittest.TestCase):
    def spec(self, **changes):
        values = dict(
            namespace="nt-0123456789",
            interface="ntwg1234",
            peer_public_key=base64.b64encode(bytes(range(32))).decode(),
            endpoint_address="198.51.100.2",
            endpoint_port=51820,
            tunnel_address="10.42.0.2/32",
            peer_allowed_ips=("0.0.0.0/0", "::/0"),
        )
        values.update(changes)
        return TunnelSpecification(**values)

    def test_public_plan_never_claims_execution_or_contains_private_keys(self):
        plan = self.spec().public_plan()
        self.assertFalse(plan["network_changes_applied"])
        self.assertFalse(plan["ownership_verified"])
        self.assertTrue(plan["requires_private_key_out_of_band"])
        self.assertNotIn("private_key", plan)

    def test_ipv6_endpoint_is_bracketed(self):
        self.assertEqual(self.spec(endpoint_address="2001:db8::1").public_plan()["endpoint"], "[2001:db8::1]:51820")

    def test_rejects_bad_identifiers(self):
        for change in ({"namespace": "../unsafe"}, {"interface": "wg0"}, {"interface": "ntwg1234;id"}):
            with self.subTest(change=change), self.assertRaises(ProvisioningError):
                self.spec(**change)

    def test_rejects_invalid_public_keys(self):
        for key in ("x" * 44, "!" * 44, base64.b64encode(b"short").decode()):
            with self.subTest(key=key), self.assertRaises(ProvisioningError):
                self.spec(peer_public_key=key)

    def test_rejects_endpoint_and_port_ambiguity(self):
        for change in (
            {"endpoint_address": "example.com"},
            {"endpoint_address": "127.0.0.1"},
            {"endpoint_port": True},
            {"endpoint_port": 65536},
        ):
            with self.subTest(change=change), self.assertRaises(ProvisioningError):
                self.spec(**change)

    def test_rejects_invalid_tunnel_and_allowed_networks(self):
        for change in (
            {"tunnel_address": "not-an-address"},
            {"peer_allowed_ips": ()},
            {"peer_allowed_ips": ("10.0.0.1/24",)},
            {"peer_allowed_ips": ("0.0.0.0/0", "0.0.0.0/0")},
            {"peer_allowed_ips": ("garbage",)},
        ):
            with self.subTest(change=change), self.assertRaises(ProvisioningError):
                self.spec(**change)
