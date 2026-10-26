"""Dry-run connection planning must never mutate VPN state."""

import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nordvpn_benchmark as b
import nordvpn_connection as c


class DryRunTests(unittest.TestCase):
    rows = [{"server": "uk715.nordvpn.com", "received": 3}]

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_disconnected_preview_only_reads_status(self, _which):
        out = io.StringIO()
        with patch.object(
            c, "run_client", return_value=c.subprocess.CompletedProcess([], 0, "Status: Disconnected\n", "")
        ) as run:
            self.assertEqual(c.preview_connection(self.rows, 1, stream=out), "ready")
            run.assert_called_once_with("status")
        self.assertIn("nordvpn connect uk715", out.getvalue())

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_existing_connection_requires_authorisation(self, _which):
        out = io.StringIO()
        with patch.object(
            c,
            "run_client",
            return_value=c.subprocess.CompletedProcess([], 0, "Status: Connected\nHostname: de123.nordvpn.com\n", ""),
        ) as run:
            self.assertEqual(c.preview_connection(self.rows, 1, stream=out), "confirmation-required")
            run.assert_called_once_with("status")
        self.assertIn("confirmation", out.getvalue())
        self.assertNotIn("would execute:", out.getvalue())

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_replacement_authorised_but_not_executed(self, _which):
        out = io.StringIO()
        with patch.object(
            c, "run_client", return_value=c.subprocess.CompletedProcess([], 0, "Status: Connected\n", "")
        ) as run:
            self.assertEqual(c.preview_connection(self.rows, 1, replace_existing=True, stream=out), "ready")
            run.assert_called_once_with("status")
        self.assertIn("would execute: nordvpn connect uk715", out.getvalue())

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_already_connected(self, _which):
        out = io.StringIO()
        with patch.object(
            c,
            "run_client",
            return_value=c.subprocess.CompletedProcess([], 0, "Status: Connected\nHostname: uk715.nordvpn.com\n", ""),
        ) as run:
            self.assertEqual(c.preview_connection(self.rows, 1, stream=out), "already-connected")
            run.assert_called_once_with("status")
        self.assertIn("no connection command needed", out.getvalue())

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_reject_unmeasured_before_status(self, _which):
        with patch.object(c, "status") as status:
            with self.assertRaisesRegex(c.ConnectionError, "no successful"):
                c.preview_connection([{"server": "uk715.nordvpn.com", "received": 0}], 1)
            status.assert_not_called()

    def test_dry_run_requires_auto_connect(self):
        with self.assertRaises(SystemExit) as exc:
            b.main(["--download", "--dry-run"])
        self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
