"""Unprivileged checks for the opt-in integrated disposable acceptance harness."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


PROBE_PATH = Path(__file__).resolve().parents[1] / "tools" / "probe_disposable_execution.py"
SPEC = importlib.util.spec_from_file_location("probe_disposable_execution", PROBE_PATH)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class DisposableProbeTests(unittest.TestCase):
    def test_dry_run_does_not_execute(self):
        with patch.object(probe, "run_probe") as run:
            self.assertEqual(probe.main([]), 0)
        run.assert_not_called()

    def test_explicit_authorisation_required(self):
        with patch.object(probe, "run_probe", return_value="nt-test") as run:
            self.assertEqual(probe.main(["--run-privileged"]), 0)
        run.assert_called_once_with()

    def test_missing_privileges_refused_before_mutation(self):
        with (
            patch.object(probe.os, "geteuid", return_value=1000),
            patch.object(probe, "execute_disposable_session") as execute,
            self.assertRaisesRegex(probe.ProbeError, "root privileges"),
        ):
            probe.run_probe()
        execute.assert_not_called()

    def test_missing_dependencies_refused_before_mutation(self):
        with (
            patch.object(probe.os, "geteuid", return_value=0),
            patch.object(probe.shutil, "which", return_value=None),
            patch.object(probe, "execute_disposable_session") as execute,
            self.assertRaisesRegex(probe.ProbeError, "missing prerequisite"),
        ):
            probe.run_probe()
        execute.assert_not_called()

    def test_privileged_failure_is_nonzero(self):
        with patch.object(probe, "run_probe", side_effect=probe.ProbeError("failure")):
            self.assertEqual(probe.main(["--run-privileged"]), 1)

    def test_command_failure_does_not_expose_command_output(self):
        from subprocess import CompletedProcess

        with (
            patch.object(probe.subprocess, "run", return_value=CompletedProcess([], 1, b"secret", b"secret")),
            self.assertRaisesRegex(probe.ProbeError, "required WireGuard command failed"),
        ):
            probe.command("wg", "genkey")


if __name__ == "__main__":
    unittest.main()
