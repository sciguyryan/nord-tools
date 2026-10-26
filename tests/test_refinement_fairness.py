"""Server-level TCP refinement selection remains fair and deterministic."""

import unittest

import nordvpn_benchmark as benchmark


class TCPRefinementFairnessTests(unittest.TestCase):
    @staticmethod
    def endpoint(server, address, port):
        return benchmark.Endpoint(f"{server}.{port}.ovpn", address, port, "tcp", server)

    @staticmethod
    def measurement(address, latency, *, received=True):
        return benchmark.Measurement(address, attempted=3, samples=[latency] * 3 if received else [], method="tcp")

    def test_multiple_ports_cannot_crowd_other_servers_out(self):
        endpoints = [self.endpoint("ad1.nordvpn.com", "192.0.2.1", port) for port in range(1000, 1030)]
        endpoints += [self.endpoint(f"je{index}.nordvpn.com", f"192.0.2.{index + 1}", 443) for index in range(1, 26)]
        results = {(e.host, e.port): self.measurement(e.host, 1 if e.host == "192.0.2.1" else 10) for e in endpoints}
        shortlist = benchmark.tcp_refinement_shortlist(endpoints, results, top=5)
        self.assertEqual(len(shortlist), 20)
        self.assertEqual(sum(address == "192.0.2.1" for address, _ in shortlist), 1)
        self.assertEqual(len({address for address, _ in shortlist}), 20)

    def test_best_survey_port_selected_and_other_ports_preserved(self):
        endpoints = [self.endpoint("ad1.nordvpn.com", "192.0.2.1", port) for port in (80, 443, 1234)]
        results = {(e.host, e.port): self.measurement(e.host, latency) for e, latency in zip(endpoints, (10, 7, 9))}
        self.assertEqual(benchmark.tcp_refinement_shortlist(endpoints, results, 10), [("192.0.2.1", 443)])
        self.assertEqual(len(benchmark.records_for(endpoints, results)), 3)

    def test_ties_are_deterministic_and_failed_ports_rank_last(self):
        endpoints = [self.endpoint("ad1.nordvpn.com", "192.0.2.1", port) for port in (1234, 443, 80)]
        results = {(e.host, e.port): self.measurement(e.host, 10, received=e.port != 80) for e in endpoints}
        expected = [("192.0.2.1", 443)]
        self.assertEqual(benchmark.tcp_refinement_shortlist(endpoints, results, 1), expected)
        self.assertEqual(benchmark.tcp_refinement_shortlist(list(reversed(endpoints)), results, 1), expected)

    def test_same_address_with_distinct_server_names_remains_distinct(self):
        endpoints = [
            self.endpoint(name, "192.0.2.1", 443 if index == 0 else 80)
            for index, name in enumerate(("ad1.nordvpn.com", "ad2.nordvpn.com"))
        ]
        results = {(e.host, e.port): self.measurement(e.host, 10) for e in endpoints}
        self.assertEqual(len(benchmark.tcp_refinement_shortlist(endpoints, results, 1)), 2)


if __name__ == "__main__":
    unittest.main()
