"""Offline paired-report comparison tests."""

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from compare_sampling import compare_pair


def report(adaptive=False, *, attempts=20, winner="ad9.nordvpn.com"):
    return {
        "schema_version": 1,
        "settings": {
            "adaptive_enabled": adaptive,
            "probe": "tcp",
            "protocol": "tcp",
            "accuracy": "balanced",
            "top": 10,
        },
        "source": {"kind": "download", "archive_sha256": "digest"},
        "methodology": {"survey_samples_per_target": 3, "refinement_additional_samples_per_target": 12},
        "measurements": [{"sent": attempts}],
        "ranking": [{"server": winner, "address": "127.0.0.1", "received": 3}],
    }


class SamplingComparisonTests(unittest.TestCase):
    def test_attempt_savings_and_matching_winner(self):
        result = compare_pair(report(), report(True, attempts=12), 10)
        self.assertEqual(result["saved_percent"], 40)
        self.assertTrue(result["same_winner"])

    def test_different_winner(self):
        result = compare_pair(report(), report(True, winner="je9.nordvpn.com"), 10)
        self.assertFalse(result["same_winner"])
        self.assertEqual(result["top_overlap"], 0)

    def test_rejects_different_probe(self):
        other = report(True)
        other["settings"]["probe"] = "icmp"
        with self.assertRaisesRegex(ValueError, "probe"):
            compare_pair(report(), other, 10)

    def test_rejects_different_archive(self):
        other = report(True)
        other["source"]["archive_sha256"] = "other"
        with self.assertRaisesRegex(ValueError, "archive_sha256"):
            compare_pair(report(), other, 10)

    def test_zero_attempts(self):
        result = compare_pair(report(attempts=0), report(True, attempts=0), 10)
        self.assertEqual(result["saved_percent"], 0)


if __name__ == "__main__":
    unittest.main()
