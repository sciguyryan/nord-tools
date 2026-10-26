"""Adaptive refinement allocation and measurement accounting."""

import unittest
from unittest.mock import patch

import nordvpn_benchmark as bench


class AdaptiveTests(unittest.TestCase):
    def make(self, value, spread=0):
        return bench.Measurement(
            "192.0.2.1", attempted=3, samples=[value - spread, value, value + spread], method="tcp"
        )

    def test_retains_leaders_and_close_candidates(self):
        results = {("a", 80): self.make(10), ("b", 80): self.make(10.5), ("c", 80): self.make(80)}
        self.assertEqual(bench.adaptive_contenders(list(results), results, 1), [("a", 80), ("b", 80)])

    def test_unresponsive_target_gets_second_chance(self):
        results = {"a": self.make(10), "b": bench.Measurement("b", attempted=3)}
        self.assertEqual(bench.adaptive_contenders(["a", "b"], results, 1), ["a", "b"])

    def test_adaptive_never_exceeds_preset_budget(self):
        targets = ["a", "b", "c"]
        measurements = {key: self.make(value) for key, value in zip(targets, (10, 11, 80))}
        calls = []

        def fake_stage(selected, count, timeout, workers, label, quiet):
            calls.append((list(selected), count))
            return {
                key: bench.Measurement(key, attempted=count, samples=[measurements[key].median] * count)
                for key in selected
            }

        with patch.object(bench, "execute_stage", side_effect=fake_stage):
            bench.adaptive_refine(targets, measurements, 12, 1, "icmp", 1, 2, True)
        self.assertEqual(calls[0], (targets, 6))
        self.assertEqual(calls[1], (["a", "b"], 6))
        self.assertEqual([measurements[key].attempted for key in targets], [15, 15, 9])

    def test_fixed_mode_unchanged(self):
        measurement = self.make(10)
        bench.merge_refinement({"a": measurement}, {"a": bench.Measurement("a", attempted=4, samples=[11, 12])})
        self.assertEqual(measurement.attempted, 7)
        self.assertEqual(len(measurement.samples), 5)


if __name__ == "__main__":
    unittest.main()
