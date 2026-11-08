"""Tests for the restricted underlay wiring between host and namespace."""

import unittest
from unittest import mock

from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_underlay_install import (
    UnderlayError,
    install_namespace_underlay,
    install_tunnel_routing,
    namespace_interface_index,
)


class RecordingRunner:
    """A scripted stand-in for privileged ip subprocesses."""

    def __init__(self, fail_at: str | None = None, links: list[dict] | None = None):
        self.calls: list[list[str]] = []
        self.fail_at = fail_at
        self.links = links if links is not None else []

    def __call__(self, argv, check=False, capture_output=True, timeout=None):
        self.calls.append(list(argv))
        command = " ".join(argv)
        if self.fail_at and self.fail_at in command:
            import subprocess

            response = subprocess.CompletedProcess(argv, 2, b"", b"kernel: failure")
            return response
        return type("R", (), {"returncode": 0, "stdout": "[]".encode()})()


def namespace_links(ns_iface: str, ifindex: int = 11) -> list[dict]:
    return [{"ifname": ns_iface, "ifindex": ifindex}]


class UnderlayWiringTests(unittest.TestCase):
    def setUp(self):
        self.seed = namespace_links("ntul0123ab")

    def test_the_full_wiring_sequence_is_ordered_and_bounded(self):
        runner = RecordingRunner()
        with mock.patch(
            "nord_tools_internal.nordvpn_underlay_install._namespace_links",
            side_effect=lambda namespace: {"ntul0123ab": namespace_links("ntul0123ab")[0]},
        ):
            index = install_namespace_underlay(
                "nt-1a2b3c4d5e6f7a8b",
                "ntul0123ab",
                "nthl0123ab",
                "10.214.0.2/30",
                "10.214.0.1/30",
                runner=runner,
            )
        self.assertEqual(index, 11)
        commands = [" ".join(call) for call in runner.calls]
        self.assertIn(commands[0], [commands[0]])
        self.assertIn("link add nthl0123ab type veth peer name ntul0123ab", commands[0])
        self.assertIn("link set ntul0123ab netns nt-1a2b3c4d5e6f7a8b", commands[1])
        self.assertIn("address add 10.214.0.1/30 dev nthl0123ab", commands[2])
        self.assertIn("address add 10.214.0.2/30 dev ntul0123ab", commands[3])
        self.assertIn("ip link set nthl0123ab up", commands[4].replace("netns exec nt-1a2b3c4d5e6f7a8b ", "ip "))
        self.assertIn("ip link set ntul0123ab up", commands[5].replace("netns exec nt-1a2b3c4d5e6f7a8b ", "ip "))

    def test_failed_wiring_deletes_only_its_own_host_end(self):
        runner = RecordingRunner(fail_at="address add 10.214.0.1/30")
        with self.assertRaises(UnderlayError):
            install_namespace_underlay(
                "nt-1a2b3c4d5e6f7a8b", "ntul0123ab", "nthl0123ab", "10.214.0.2/30", "10.214.0.1/30", runner=runner
            )
        delete = [" ".join(call) for call in runner.calls if "link del" in " ".join(call)]
        self.assertEqual(len(delete), 1)
        self.assertIn("link del dev nthl0123ab", delete[0])

    def test_invalid_names_and_addresses_are_refused_before_commands(self):
        runner = RecordingRunner()
        with self.assertRaises(RegistryError):
            install_namespace_underlay(
                "nt-fairy", "ntul0123ab", "nthl0123ab", "10.0.0.2/24", "10.0.0.1/24", runner=runner
            )
        with self.assertRaises(RegistryError):
            install_namespace_underlay(
                "nt-1a2b3c4d5e6f7a8b", "same", "same", "10.0.0.2/24", "10.0.0.1/24", runner=runner
            )
        with self.assertRaises(RegistryError):
            install_namespace_underlay(
                "nt-1a2b3c4d5e6f7a8b", "ntul0123ab", "nthl0123ab", "not-an-ip", "10.0.0.1/24", runner=runner
            )
        self.assertEqual(runner.calls, [])

    def test_routing_requires_matching_address_families(self):
        with self.assertRaises(RegistryError):
            install_tunnel_routing(
                "nt-1a2b3c4d5e6f7a8b",
                "ntwg0123abcd",
                "ntul0123ab",
                "198.51.100.10",
                ("fd00::2/128",),
                "10.214.0.1",
            )
        with self.assertRaises(RegistryError):
            install_tunnel_routing(
                "nt-1a2b3c4d5e6f7a8b",
                "ntwg0123abcd",
                "ntul0123ab",
                "198.51.100.10",
                ("10.213.240.2/32", "10.213.241.2/32"),
                "10.214.0.1",
            )

    def test_tunnel_routing_adds_default_and_endpoint_routes_only(self):
        runner = RecordingRunner(links=self.seed)
        install_tunnel_routing(
            "nt-1a2b3c4d5e6f7a8b",
            "ntwg0123abcd",
            "ntul0123ab",
            "198.51.100.10",
            ("10.213.240.2/32", "fd42:213::2/128"),
            "10.214.0.1",
            runner=runner,
        )
        joined = [" ".join(call) for call in runner.calls]
        self.assertIn("route add 198.51.100.10/32 via 10.214.0.1 dev ntul0123ab", " ".join(joined))
        self.assertTrue(
            any("ip -4 -n" in command and "route add default dev ntwg0123abcd" in command for command in joined)
        )
        self.assertTrue(
            any("ip -6 -n" in command and "route add default dev ntwg0123abcd" in command for command in joined)
        )
        self.assertFalse(any("flush" in command for command in joined))

    def test_ipv6_default_route_failure_is_not_ignored(self):
        runner = RecordingRunner(fail_at="ip -6 -n")
        with self.assertRaises(UnderlayError):
            install_tunnel_routing(
                "nt-1a2b3c4d5e6f7a8b",
                "ntwg0123abcd",
                "ntul0123ab",
                "198.51.100.10",
                ("10.213.240.2/32", "fd42:213::2/128"),
                "10.214.0.1",
                runner=runner,
            )
        self.assertEqual(len(runner.calls), 3)
        self.assertTrue(all("-n nt-1a2b3c4d5e6f7a8b" in " ".join(call) for call in runner.calls))
        self.assertFalse(any("flush" in call or "replace" in call for call in runner.calls))

    def test_interface_index_requires_membership(self):
        with mock.patch(
            "nord_tools_internal.nordvpn_underlay_install._namespace_links",
            side_effect=lambda namespace: {"ntul0123ab": namespace_links("ntul0123ab")[0]},
        ):
            self.assertEqual(namespace_interface_index("nt-1a2b3c4d5e6f7a8b", "ntul0123ab"), 11)
            with self.assertRaises(UnderlayError):
                namespace_interface_index("nt-1a2b3c4d5e6f7a8b", "ntwgnonexistent")


if __name__ == "__main__":
    unittest.main()
