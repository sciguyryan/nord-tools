"""Offline regression tests for the disposable endpoint exception probe."""

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("endpoint_probe", ROOT / "tools" / "probe_endpoint_exception.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class EndpointProbeTests(unittest.TestCase):
    def test_dry_run_does_not_execute_commands(self):
        with patch.object(probe, "run", side_effect=AssertionError("unexpected execution")):
            self.assertEqual(probe.main([]), 0)

    def test_candidate_contains_only_one_endpoint_exception(self):
        for _, address, port in probe.ENDPOINTS:
            with self.subTest(address=address):
                rules = probe.probe_rules("vp123", address, port)
                self.assertEqual(rules.count('comment "endpoint-allow"'), 1)
                self.assertEqual(rules.count('comment "underlay-deny"'), 1)
                self.assertIn(f"daddr {address} udp dport {port} counter accept", rules)
                self.assertIn("policy drop", rules)

    def test_counter_requires_unique_evidence(self):
        self.assertEqual(
            probe.counter('counter packets 2 bytes 10 accept comment "endpoint-allow"', "endpoint-allow"), 2
        )
        for output in (
            "",
            'counter packets 2 bytes 10 accept comment "endpoint-allow"\ncounter packets 3 bytes 20 accept comment "endpoint-allow"',
        ):
            with self.subTest(output=output), self.assertRaises(probe.EndpointProbeError):
                probe.counter(output, "endpoint-allow")

    def test_packet_generator_is_numeric_and_udp(self):
        for family, address, port in probe.ENDPOINTS:
            cmd = probe.packet_command("vpnprobe-test", family, address, port)
            self.assertEqual(cmd[:4], ["ip", "netns", "exec", "vpnprobe-test"])
            self.assertEqual(cmd[-3:], [family, address, str(port)])

    def test_cleanup_after_setup_failure(self):
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
