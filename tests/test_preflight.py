"""Offline preflight checks; no network operations are permitted."""

import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nordvpn_benchmark as b
import nordvpn_connection as c


class PreflightTests(unittest.TestCase):
    @staticmethod
    def result(output, returncode=0):
        from subprocess import CompletedProcess

        return CompletedProcess(["nordvpn", "status"], returncode, output, "")

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_connected_blocks_without_override(self, _which):
        output = io.StringIO()
        with patch.object(
            c, "run_client", return_value=self.result("Status: Connected\nCurrent server: uk715.nordvpn.com\n")
        ) as run:
            self.assertFalse(c.benchmark_preflight(stream=output))
            run.assert_called_once_with("status")
        self.assertIn("nordvpn disconnect", output.getvalue())

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_connected_override_warns(self, _which):
        output = io.StringIO()
        with patch.object(c, "run_client", return_value=self.result("Status: Connected\n")):
            self.assertTrue(c.benchmark_preflight(allow_active_vpn=True, stream=output))
        self.assertIn("current network path", output.getvalue())

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_disconnected_continues(self, _which):
        with patch.object(c, "run_client", return_value=self.result("Status: Disconnected\n")):
            self.assertTrue(c.benchmark_preflight(stream=io.StringIO()))

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_unrecognised_status_reports_uncertainty(self, _which):
        output = io.StringIO()
        with patch.object(c, "run_client", return_value=self.result("Changed output\n")):
            self.assertTrue(c.benchmark_preflight(stream=output))
        self.assertIn("cannot establish", output.getvalue())

    @patch.object(c.shutil, "which", return_value=None)
    def test_missing_client_reports_uncertainty(self, _which):
        output = io.StringIO()
        self.assertTrue(c.benchmark_preflight(stream=output))
        self.assertIn("unavailable", output.getvalue())

    def test_blocked_main_does_not_download_or_probe(self):
        with (
            patch.object(c, "benchmark_preflight", return_value=False),
            patch.object(b, "extract_archive") as extract,
            patch.object(b, "execute_stage") as probe,
            patch.object(b.shutil, "which", return_value="/usr/bin/ping"),
        ):
            self.assertEqual(b.main(["--download"]), 2)
            extract.assert_not_called()
            probe.assert_not_called()

    def test_list_regions_skips_preflight(self):
        with patch.object(c, "benchmark_preflight") as check:
            self.assertEqual(b.main(["--list-region-lists"]), 0)
            check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
