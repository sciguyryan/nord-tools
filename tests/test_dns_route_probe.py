"""Non-privileged route-confinement probe regression tests."""

import importlib.util
import ipaddress
import pathlib
import sys
import unittest
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location("dns_route_probe", TOOLS / "probe_dns_route_confinement.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class DnsRouteProbeTests(unittest.TestCase):
    def test_dry_run_never_runs_commands(self):
        with patch.object(probe, "run", side_effect=AssertionError("unexpected command")):
            self.assertEqual(probe.main([]), 0)

    def test_dns_targets_are_outside_connected_underlay_networks(self):
        underlay = {
            "ipv4": ipaddress.ip_network("198.18.0.0/30"),
            "ipv6": ipaddress.ip_network("fd42:4::/64"),
        }
        for family, address, _ in probe.DNS_TARGETS:
            with self.subTest(family=family):
                self.assertNotIn(ipaddress.ip_address(address), underlay[family])

    def test_route_device_requires_exactly_one_device(self):
        self.assertEqual(probe.route_device("198.18.0.53 dev tunnel-sim src 0.0.0.0"), "tunnel-sim")
        self.assertIsNone(probe.route_device("unreachable 198.18.0.53"))
        self.assertIsNone(probe.route_device("dev tunnel-sim dev underlay"))

    def test_up_route_must_select_tunnel(self):
        for output in ("198.18.0.53 dev vp123", "unreachable 198.18.0.53"):
            with (
                patch.object(probe, "run", return_value=probe.subprocess.CompletedProcess([], 0, output, "")),
                self.assertRaises(probe.RouteProbeError),
            ):
                probe.assert_dns_route("test", "ipv4", "198.18.0.53", "-4", tunnel_up=True, peer="vp123")

    def test_down_route_rejects_underlay_and_ambiguous_results(self):
        for output in ("198.18.0.53 dev vp123", "198.18.0.53 dev eth0", "unreachable"):
            with (
                patch.object(probe, "run", return_value=probe.subprocess.CompletedProcess([], 0, output, "")),
                self.assertRaises(probe.RouteProbeError),
            ):
                probe.assert_dns_route("test", "ipv4", "198.18.0.53", "-4", tunnel_up=False, peer="vp123")

    def test_down_route_accepts_unreachable_kernel_result(self):
        with patch.object(
            probe, "run", return_value=probe.subprocess.CompletedProcess([], 2, "", "Network is unreachable")
        ):
            probe.assert_dns_route("test", "ipv6", "fd42:5::53", "-6", tunnel_up=False, peer="vp123")

    def test_down_route_rejects_unrelated_command_failure(self):
        with (
            patch.object(probe, "run", return_value=probe.subprocess.CompletedProcess([], 1, "", "permission denied")),
            self.assertRaises(probe.RouteProbeError),
        ):
            probe.assert_dns_route("test", "ipv6", "fd42:5::53", "-6", tunnel_up=False, peer="vp123")

    def test_ipv6_default_is_installed_before_route_checks(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if argv[:3] == ["ip", "netns", "exec"] and "route" in argv:
                return probe.subprocess.CompletedProcess(argv, 0, "fd42:5::53 dev tunnel-sim", "")
            return probe.subprocess.CompletedProcess(argv, 0, "", "")

        with patch.object(probe, "run", side_effect=fake_run), patch.object(probe, "assert_dns_route"):
            probe.probe("vpnprobe-test")
        ipv6_default = ["ip", "-n", "vpnprobe-test", "-6", "route", "add", "default", "dev", "tunnel-sim"]
        self.assertIn(ipv6_default, calls)
        self.assertLess(
            calls.index(ipv6_default), calls.index(["ip", "-n", "vpnprobe-test", "link", "set", "tunnel-sim", "down"])
        )

    def test_cleanup_on_setup_failure(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if len(calls) == 3:
                raise probe.subprocess.CalledProcessError(1, argv)
            return probe.subprocess.CompletedProcess(argv, 0, "", "")

        with patch.object(probe, "run", side_effect=fake_run), self.assertRaises(probe.subprocess.CalledProcessError):
            probe.probe("vpnprobe-test")
        self.assertEqual(
            calls[-2:], [["ip", "netns", "del", "vpnprobe-test-r"], ["ip", "netns", "del", "vpnprobe-test"]]
        )
