"""Offline safety checks for the opt-in two-profile privileged acceptance probe."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


PROBE_PATH = Path(__file__).resolve().parents[1] / "tools" / "probe_selected_profile_retirement.py"
spec = importlib.util.spec_from_file_location("probe_selected_profile_retirement", PROBE_PATH)
assert spec is not None and spec.loader is not None
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class SelectedProfileProbeTests(unittest.TestCase):
    def test_dry_run_never_enters_privileged_path(self):
        with patch.object(probe, "run_probe", side_effect=AssertionError("unexpected mutation")):
            self.assertEqual(probe.main([]), 0)

    def test_privileged_failure_is_reported(self):
        with patch.object(probe, "run_probe", side_effect=probe.ProbeError("expected refusal")):
            self.assertEqual(probe.main(["--run-privileged"]), 1)


if __name__ == "__main__":
    unittest.main()
