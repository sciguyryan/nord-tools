import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nordvpn_connection as c


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{"server": "uk715.nordvpn.com", "received": 3}]

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_connect_and_verify(self, _which):
        with patch.object(c, "run_client") as run:
            run.side_effect = [
                self.result("Status: Disconnected\n"),
                self.result("Connecting..."),
                self.result("Status: Connected\nCurrent server: uk715.nordvpn.com\n"),
            ]
            self.assertEqual(c.connect(self.rows, 1), "uk715.nordvpn.com")
            self.assertEqual(run.call_args_list[1].args, ("connect", "uk715"))

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_existing_connection_not_replaced(self, _which):
        with patch.object(
            c, "run_client", return_value=self.result("Status: Connected\nCurrent server: de123.nordvpn.com\n")
        ) as run:
            with self.assertRaisesRegex(c.ConnectionError, "unchanged"):
                c.connect(self.rows, 1)
            self.assertEqual(run.call_count, 1)

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_mismatch_is_failure(self, _which):
        with patch.object(c, "run_client") as run:
            run.side_effect = [
                self.result("Status: Disconnected\n"),
                self.result("ok"),
                self.result("Status: Connected\nCurrent server: de123.nordvpn.com\n"),
            ]
            with self.assertRaisesRegex(c.ConnectionError, "not requested"):
                c.connect(self.rows, 1)

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_connected_without_identity_is_unverified_not_failed(self, _which):
        import io

        output = io.StringIO()
        with patch.object(c, "run_client") as run:
            run.side_effect = [
                self.result("Status: Disconnected\n"),
                self.result("Connection established"),
                self.result("Status: Connected\n"),
            ]
            self.assertIsNone(c.connect(self.rows, 1, stream=output))
        self.assertIn("Cannot verify", output.getvalue())
        self.assertNotIn("Connected and verified", output.getvalue())

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_unrecognised_status_fails_closed(self, _which):
        with (
            patch.object(c, "run_client", return_value=self.result("Something changed\n")),
            self.assertRaisesRegex(c.ConnectionError, "not recognised"),
        ):
            c.connect(self.rows, 1)

    @patch.object(c.sys, "platform", "linux")
    @patch.object(c.shutil, "which", return_value="/usr/bin/nordvpn")
    def test_unrecognised_profile_rejected(self, _which):
        with patch.object(c, "run_client") as run:
            with self.assertRaisesRegex(c.ConnectionError, "cannot derive"):
                c.connect([{"server": "custom.ovpn", "received": 3}], 1)
            run.assert_not_called()

    @staticmethod
    def result(stdout, returncode=0):
        from subprocess import CompletedProcess

        return CompletedProcess(["nordvpn"], returncode, stdout, "")


if __name__ == "__main__":
    unittest.main()


class StatusIdentityTests(unittest.TestCase):
    def test_hostname_field(self):
        self.assertEqual(c.parse_status("Status: Connected\nHostname: uk715.nordvpn.com\n").server, "uk715.nordvpn.com")

    def test_short_server_id(self):
        self.assertEqual(c.parse_status("Status: Connected\nCurrent server: UK715\n").server, "uk715.nordvpn.com")

    def test_unknown_identity_remains_unverified(self):
        self.assertIsNone(c.parse_status("Status: Connected\nCountry: United Kingdom\n").server)

    def test_conflicting_identity_rejected(self):
        with self.assertRaisesRegex(c.ConnectionError, "conflicting"):
            c.parse_status("Status: Connected\nHostname: uk715.nordvpn.com\nCurrent server: de123.nordvpn.com\n")

    def test_invalid_identity_rejected(self):
        with self.assertRaisesRegex(c.ConnectionError, "unrecognised server identity"):
            c.parse_status("Status: Connected\nHostname: vpn.example.com\n")

    def test_duplicate_status_rejected(self):
        with self.assertRaisesRegex(c.ConnectionError, "not recognised"):
            c.parse_status("Status: Connected\nStatus: Disconnected\n")
