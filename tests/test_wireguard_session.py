"""Offline tests for the experimental disposable WireGuard session."""

import base64
import os
from unittest import TestCase
from unittest.mock import Mock, patch

from nord_tools_internal.nordvpn_namespace_ownership import OwnedNamespace
from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification
from nord_tools_internal.nordvpn_wireguard_session import SessionError, configure_disposable_wireguard


class SessionTests(TestCase):
    def setUp(self):
        self.spec = TunnelSpecification(
            "nt-0123456789",
            "ntwg1234",
            base64.b64encode(bytes(range(32))).decode(),
            "198.51.100.2",
            51820,
            "10.42.0.2/32",
            ("10.42.0.1/32",),
        )
        self.owned = OwnedNamespace(self.spec.namespace, 5, 1, 2)
        self.key = base64.b64encode(bytes(range(32)))

    def execute(self, key=None):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, self.key if key is None else key)
        finally:
            os.close(write_fd)
        try:
            configure_disposable_wireguard(self.spec, self.owned, read_fd)
        finally:
            os.close(read_fd)

    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_command_sequence_and_no_key_in_arguments(self, verify, run):
        self.execute()
        self.assertEqual(run.call_count, 4)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[0][:5], ["ip", "-n", self.spec.namespace, "link", "add"])
        self.assertIn("private-key", commands[1])
        self.assertNotIn("private-key " + self.key.decode(), repr(commands))
        self.assertNotIn(self.key.decode(), repr(commands[0] + commands[2] + commands[3]))
        self.assertEqual(commands[-1][-1], "up")
        self.assertGreaterEqual(verify.call_count, 4)

    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_invalid_key_never_mutates(self, verify, run):
        with self.assertRaises(ValueError):
            self.execute(b"bad")
        run.assert_not_called()

    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_mismatched_namespace_never_mutates(self, verify, run):
        self.owned.name = "nt-ffffffff"
        with self.assertRaises(SessionError):
            self.execute()
        run.assert_not_called()

    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_failed_creation_does_not_attempt_further_commands(self, verify, run):
        run.side_effect = SessionError("failed")
        with self.assertRaises(SessionError):
            self.execute()
        run.assert_called_once()

    @patch("nord_tools_internal.nordvpn_wireguard_session._run")
    @patch.object(OwnedNamespace, "verify")
    def test_identity_change_halts_sequence(self, verify, run):
        verify.side_effect = [None, None, SessionError("identity changed")]
        with self.assertRaises(SessionError):
            self.execute()
        run.assert_called_once()

    @patch("nord_tools_internal.nordvpn_wireguard_session.subprocess.run")
    def test_command_errors_do_not_echo_subprocess_output(self, run):
        from nord_tools_internal.nordvpn_wireguard_session import _run

        run.return_value = Mock(returncode=1, stdout=b"private", stderr=b"secret")
        with self.assertRaisesRegex(SessionError, "command failed") as error:
            _run(["wg", "show"])
        self.assertNotIn("secret", str(error.exception))
