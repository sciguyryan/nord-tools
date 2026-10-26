"""Regression tests for optional, non-ranking stability diagnostics."""

import unittest

import nordvpn_benchmark as benchmark


class StabilityTests(unittest.TestCase):
    def test_deterministic_bootstrap(self):
        samples = [8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 9.0]
        first = benchmark.median_interval(samples, "server:80")
        self.assertEqual(first, benchmark.median_interval(samples, "server:80"))
        self.assertLessEqual(first[0], first[1])

    def test_insufficient_samples(self):
        self.assertIsNone(benchmark.median_interval([1.0] * 7, "server"))

    def test_report_does_not_reorder_or_mutate(self):
        a = benchmark.Endpoint("a.ovpn", "192.0.2.1", 80, "tcp", "aa1.nordvpn.com")
        b = benchmark.Endpoint("b.ovpn", "192.0.2.2", 80, "tcp", "bb1.nordvpn.com")
        measurements = {
            (a.host, 80): benchmark.Measurement(a.host, 10, [10.0] * 10, method="tcp"),
            (b.host, 80): benchmark.Measurement(b.host, 10, [20.0] * 10, method="tcp"),
        }
        ranked = benchmark.distinct_servers(benchmark.records_for([a, b], measurements))
        before = [dict(row) for row in ranked]
        report = benchmark.stability_report(ranked, measurements)
        self.assertIn("ranked leader", report)
        self.assertIn("non-overlapping intervals", report)
        self.assertEqual(ranked, before)

    def test_report_requires_refined_sample_count(self):
        endpoint = benchmark.Endpoint("a.ovpn", "192.0.2.1", 443, "tcp", "aa1.nordvpn.com")
        measurement = benchmark.Measurement(endpoint.host, 3, [1.0, 2.0, 3.0], method="tcp")
        records = benchmark.records_for([endpoint], {(endpoint.host, 443): measurement})
        self.assertIn("insufficient samples", benchmark.stability_report(records, {(endpoint.host, 443): measurement}))

    def test_no_responsive_candidates(self):
        self.assertIn("No responsive servers", benchmark.stability_report([], {}))


if __name__ == "__main__":
    unittest.main()
