"""Offline checks for protocol-aware reachability measurements."""

import unittest
from unittest.mock import patch

import nordvpn_benchmark as b


class TCPProbeTests(unittest.TestCase):
    def test_auto_mode_is_rejected(self):
        with self.assertRaises(SystemExit) as caught:
            b.main(["--download", "--probe", "auto"])
        self.assertEqual(caught.exception.code, 2)

    def test_tcp_requires_tcp_profiles(self):
        with self.assertRaises(SystemExit) as caught:
            b.main(["--download", "--probe", "tcp"])
        self.assertEqual(caught.exception.code, 2)

    def test_tcp_success(self):
        class Socket:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        with patch.object(b.socket, "create_connection", return_value=Socket()) as connect:
            result = b.tcp_probe("192.0.2.1", 443, 3, 0.5)
        self.assertEqual(result.method, "tcp")
        self.assertEqual(len(result.samples), 3)
        self.assertEqual(result.loss, 0)
        connect.assert_called_with(("192.0.2.1", 443), timeout=0.5)

    def test_tcp_failure_does_not_imply_vpn_offline(self):
        with patch.object(b.socket, "create_connection", side_effect=OSError("refused")):
            result = b.tcp_probe("192.0.2.1", 443, 2, 0.5)
        self.assertFalse(result.samples)
        self.assertEqual(result.loss, 100)
        self.assertIn("TCP connection failed", result.error)

    def test_tcp_ports_are_distinct(self):
        endpoints = [b.Endpoint("test.ovpn", "192.0.2.1", port, "tcp", "nl1.nordvpn.com") for port in (443, 1194)]
        measurements = {(e.host, e.port): b.Measurement(e.host, 1, [10.0], method="tcp") for e in endpoints}
        records = b.records_for(endpoints, measurements)
        self.assertEqual(len(b.distinct_servers(records)), 1)
        self.assertEqual(len(records), 2)  # Per-port export detail is preserved.
        self.assertIn("Probe", b.format_results(records, 2, True))

    def test_tcp_progress_ends_with_newline(self):
        import io
        from unittest.mock import patch

        output = io.StringIO()
        with (
            patch.object(b.sys, "stderr", output),
            patch.object(output, "isatty", return_value=True),
            patch.object(b, "tcp_probe", return_value=b.Measurement("192.0.2.1", 1, [1.0], method="tcp")),
        ):
            b.execute_tcp_stage([("192.0.2.1", 443)], 1, 0.5, 1, "TCP refinement", False)
        self.assertTrue(output.getvalue().endswith("\n"))

    def test_icmp_and_tcp_not_interchangeable(self):
        endpoints = [
            b.Endpoint("icmp.ovpn", "192.0.2.1", 53, "udp", "nl1.nordvpn.com"),
            b.Endpoint("tcp.ovpn", "192.0.2.2", 443, "tcp", "nl2.nordvpn.com"),
        ]
        measurements = {
            "192.0.2.1": b.Measurement("192.0.2.1", 1, [40.0]),
            ("192.0.2.2", 443): b.Measurement("192.0.2.2", 1, [10.0], method="tcp"),
        }
        records = b.records_for(endpoints, measurements)
        self.assertEqual({r["probe"] for r in records}, {"icmp", "tcp"})
        # The pipeline must never construct such a mixed-method record set.


if __name__ == "__main__":
    unittest.main()
