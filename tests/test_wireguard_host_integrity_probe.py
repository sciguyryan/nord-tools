"""Offline regression checks for the disposable host-integrity probe."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from tools import probe_wireguard_host_integrity as integrity


class HostIntegrityProbeTests(unittest.TestCase):
    def test_dry_run_never_executes(self):
        with patch.object(integrity, "experiment") as experiment, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(integrity.main([]), 0)
        experiment.assert_not_called()
        self.assertIn("DRY RUN", output.getvalue())

    def test_matching_observations_pass(self):
        with redirect_stdout(io.StringIO()) as output:
            integrity.verify({"routes": "a"}, {"routes": "a"})
        self.assertIn("PASS", output.getvalue())

    def test_changed_host_state_fails(self):
        with self.assertRaisesRegex(integrity.IntegrityError, "routes"):
            integrity.verify({"routes": "a"}, {"routes": "b"})

    def test_missing_observation_fails(self):
        with self.assertRaisesRegex(integrity.IntegrityError, "set changed"):
            integrity.verify({"routes": "a"}, {})

    def test_experiment_failure_still_observes_afterwards(self):
        with (
            patch.object(integrity, "observe", side_effect=[{"routes": "a"}, {"routes": "a"}]) as observation,
            patch.object(integrity, "experiment", side_effect=integrity.HarnessError("injected")),
            redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(integrity.IntegrityError, "injected"),
        ):
            integrity.probe("abcdef")
        self.assertEqual(observation.call_count, 2)

    def test_experiment_and_observations_pass(self):
        with (
            patch.object(integrity, "observe", side_effect=[{"routes": "a"}, {"routes": "a"}]),
            patch.object(integrity, "experiment") as experiment,
            redirect_stdout(io.StringIO()),
        ):
            integrity.probe("abcdef")
        experiment.assert_called_once_with("abcdef")


if __name__ == "__main__":
    unittest.main()
