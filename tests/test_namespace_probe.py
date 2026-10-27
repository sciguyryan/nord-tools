"""Non-privileged checks for the opt-in namespace feasibility probe."""

import importlib.util
import pathlib
import unittest
from unittest.mock import patch

PATH = pathlib.Path(__file__).resolve().parents[1] / "tools" / "probe_namespace_isolation.py"
SPEC = importlib.util.spec_from_file_location("namespace_probe", PATH)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class NamespaceProbeTests(unittest.TestCase):
    def test_dry_run_does_not_execute_commands(self):
        with patch.object(probe, "run", side_effect=AssertionError("must not execute")):
            self.assertEqual(probe.main([]), 0)

    def test_commands_are_namespaced_and_no_host_routes_changed(self):
        commands = probe.commands("vpnprobe-test")
        self.assertEqual(commands[0], ["ip", "netns", "add", "vpnprobe-test"])
        self.assertTrue(
            all(
                "vpnprobe-test" in " ".join(c) or probe.underlay_interface("vpnprobe-test") in " ".join(c)
                for c in commands
            )
        )
        self.assertNotIn("ip route replace", " ".join(" ".join(c) for c in commands))

    def test_generated_interface_names_fit_linux_limit(self):
        for namespace in ("vpnprobe-54411c6e", "vpnprobe-test", "vpnprobe-" + "a" * 60):
            interface = probe.underlay_interface(namespace)
            self.assertLessEqual(len(interface.encode("ascii")), 15)
            self.assertIn(
                ["ip", "link", "add", interface, "type", "veth", "peer", "name", "underlay"], probe.commands(namespace)
            )
        self.assertNotEqual(probe.underlay_interface("vpnprobe-a"), probe.underlay_interface("vpnprobe-b"))

    def test_firewall_blocks_underlay_and_allows_simulated_tunnel(self):
        self.assertIn("policy drop", probe.FIREWALL)
        self.assertIn('oifname "tunnel-sim" accept', probe.FIREWALL)
        self.assertNotIn('oifname "underlay" accept', probe.FIREWALL)

    def test_cleanup_on_failure_after_namespace_creation(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if len(calls) == 3:
                raise probe.subprocess.CalledProcessError(1, argv)
            return probe.subprocess.CompletedProcess(argv, 0, "", "")

        with (
            patch.object(probe, "run", side_effect=fake_run),
            self.assertRaises(probe.subprocess.CalledProcessError),
        ):
            probe.probe("vpnprobe-test")
        self.assertEqual(
            calls[-2:], [["ip", "netns", "del", "vpnprobe-test-r"], ["ip", "netns", "del", "vpnprobe-test"]]
        )


if __name__ == "__main__":
    unittest.main()


class UnderlayCounterTests(unittest.TestCase):
    def test_counter_requires_explicit_drop_rule(self):
        text = 'meta nfproto ipv4 oifname "vp5c4c2da28b" counter packets 3 bytes 252 drop # handle 4'
        self.assertEqual(probe.dropped_packets(text, "vp5c4c2da28b"), 3)
        with self.assertRaises(probe.ProbeError):
            probe.dropped_packets("policy drop; counter packets 3 bytes 252", "vp5c4c2da28b")
        with self.assertRaises(probe.ProbeError):
            probe.dropped_packets(text, "different-p")

    def test_underlay_has_explicit_route_and_counted_drop(self):
        commands = probe.commands("vpnprobe-test")
        self.assertIn(
            ["ip", "-n", "vpnprobe-test", "route", "add", "198.18.0.1/32", "dev", "vp5c4c2da28b"],
            commands,
        )
        self.assertIn('meta nfproto ipv4 oifname "{underlay}" counter drop', probe.FIREWALL)

    def test_ipv6_probe_has_explicit_underlay_route_and_drop_counter(self):
        commands = probe.commands("vpnprobe-test")
        self.assertIn(
            ["ip", "-n", "vpnprobe-test", "-6", "route", "add", "fd42:4::1/128", "dev", "vp5c4c2da28b"],
            commands,
        )
        self.assertIn('meta nfproto ipv6 oifname "{underlay}" counter drop', probe.FIREWALL)
        output = 'meta nfproto ipv6 oifname "vp5c4c2da28b" counter packets 2 bytes 160 drop'
        self.assertEqual(probe.dropped_packets(output, "vp5c4c2da28b", "ipv6"), 2)
        with self.assertRaises(probe.ProbeError):
            probe.dropped_packets(output, "vp5c4c2da28b", "ipv4")

    def test_probe_requires_counter_increase(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if argv[-5:] == ["list", "chain", "inet", "vpn_probe", "output"]:
                return probe.subprocess.CompletedProcess(
                    argv,
                    0,
                    'meta nfproto ipv4 oifname "vp5c4c2da28b" counter packets 0 bytes 0 drop',
                    "",
                )
            if "ping" in argv:
                return probe.subprocess.CompletedProcess(argv, 1, "", "")
            return probe.subprocess.CompletedProcess(argv, 0, "", "")

        with (
            patch.object(probe, "run", side_effect=fake_run),
            self.assertRaisesRegex(probe.ProbeError, "counter did not advance"),
        ):
            probe.probe("vpnprobe-test")
        self.assertEqual(
            calls[-2:],
            [
                ["ip", "netns", "del", "vpnprobe-test-r"],
                ["ip", "netns", "del", "vpnprobe-test"],
            ],
        )
