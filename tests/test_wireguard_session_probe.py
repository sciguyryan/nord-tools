"""Non-privileged tests for the opt-in disposable configuration probe."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


PATH = Path(__file__).resolve().parents[1] / "tools" / "probe_wireguard_session.py"
SPEC = importlib.util.spec_from_file_location("probe_wireguard_session", PATH)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class SessionProbeTests(unittest.TestCase):
    def test_dry_run_does_not_execute(self):
        with patch.object(probe, "run_probe") as run:
            self.assertEqual(probe.main([]), 0)
            run.assert_not_called()

    def test_explicit_confirmation_runs_probe(self):
        with patch.object(probe, "run_probe", return_value="nt-0123456789abcdef") as run:
            self.assertEqual(probe.main(["--run-privileged"]), 0)
            run.assert_called_once_with()

    def test_probe_failure_is_nonzero(self):
        with patch.object(probe, "run_probe", side_effect=probe.ProbeError("failed")):
            self.assertEqual(probe.main(["--run-privileged"]), 1)

    def test_missing_root_refuses_before_mutation(self):
        with (
            patch.object(probe.os, "geteuid", return_value=1000),
            patch.object(probe, "command") as command,
            self.assertRaisesRegex(probe.ProbeError, "root"),
        ):
            probe.run_probe()
        command.assert_not_called()

    def test_missing_dependency_refuses_before_mutation(self):
        with (
            patch.object(probe.os, "geteuid", return_value=0),
            patch.object(probe.shutil, "which", return_value=None),
            self.assertRaisesRegex(probe.ProbeError, "missing prerequisite"),
        ):
            probe.run_probe()


if __name__ == "__main__":
    unittest.main()
